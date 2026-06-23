// Package sqlite implements the metadata store on SQLite via the pure-Go
// modernc driver (no cgo, so the static binary stays static). It is the
// single-box backend; postgres is the horizontal-scale alternative.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/hivecom/orbit-depot/internal/store"
)

// Store is the SQLite-backed metadata store.
type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// dsn builds the connection string with pragmas: a busy timeout so concurrent
// writers retry instead of failing, WAL for read/write concurrency, and foreign
// keys on.
func dsn(path string) string {
	return "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS uploads (
    object_key        TEXT PRIMARY KEY,
    uploader_account  TEXT NOT NULL,
    uploader_issuer   TEXT NOT NULL,
    file_size         INTEGER NOT NULL,
    content_type      TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    uploaded_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uploads_owner ON uploads(uploader_account, uploader_issuer);
CREATE INDEX IF NOT EXISTS idx_uploads_uploaded_at ON uploads(uploaded_at);

CREATE TABLE IF NOT EXISTS api_keys (
    id            TEXT PRIMARY KEY,
    hash          TEXT NOT NULL UNIQUE,
    owner_account TEXT NOT NULL,
    owner_issuer  TEXT NOT NULL,
    label         TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    expires_at    INTEGER,
    last_used_at  INTEGER,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_account, owner_issuer);`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// RecordUpload writes the metadata row for a presigned upload.
func (s *Store) RecordUpload(ctx context.Context, u store.Upload) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO uploads (object_key, uploader_account, uploader_issuer, file_size, content_type, original_filename, uploaded_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ObjectKey, u.UploaderAccount, u.UploaderIssuer, u.FileSize, u.ContentType, u.OriginalFilename, u.UploadedAt.Unix())
	if err != nil {
		return fmt.Errorf("record upload: %w", err)
	}
	return nil
}

// DeleteUpload removes an upload row owned by account/issuer. It returns
// store.ErrNotFound when there is no such owned row.
func (s *Store) DeleteUpload(ctx context.Context, objectKey, account, issuer string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM uploads WHERE object_key = ? AND uploader_account = ? AND uploader_issuer = ?`,
		objectKey, account, issuer)
	if err != nil {
		return fmt.Errorf("delete upload: %w", err)
	}
	return notFoundIfZero(res)
}

// DeleteUploadAny removes an upload row regardless of owner (the moderation
// path). Returns store.ErrNotFound when there is no such row.
func (s *Store) DeleteUploadAny(ctx context.Context, objectKey string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM uploads WHERE object_key = ?`, objectKey)
	if err != nil {
		return fmt.Errorf("delete upload (any): %w", err)
	}
	return notFoundIfZero(res)
}

const uploadColumns = `object_key, uploader_account, uploader_issuer, file_size, content_type, original_filename, uploaded_at`

// allowedSort and allowedOrder whitelist the only values that may reach the
// ORDER BY clause. The query strings are looked up here, never interpolated.
var (
	allowedSort  = map[string]string{"uploaded_at": "uploaded_at", "file_size": "file_size"}
	allowedOrder = map[string]string{"asc": "ASC", "desc": "DESC"}
)

// ListUploads returns a page of uploads matching q plus the total matching count.
func (s *Store) ListUploads(ctx context.Context, q store.ListUploadsQuery) ([]store.Upload, int, error) {
	where, args := uploadFilter(q)

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count uploads: %w", err)
	}

	sortCol, ok := allowedSort[q.Sort]
	if !ok {
		sortCol = "uploaded_at"
	}
	order, ok := allowedOrder[q.Order]
	if !ok {
		order = "DESC"
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+uploadColumns+` FROM uploads`+where+` ORDER BY `+sortCol+` `+order+` LIMIT ? OFFSET ?`,
		append(args, q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list uploads: %w", err)
	}
	defer rows.Close()

	var uploads []store.Upload
	for rows.Next() {
		u, err := scanUpload(rows)
		if err != nil {
			return nil, 0, err
		}
		uploads = append(uploads, u)
	}
	return uploads, total, rows.Err()
}

// uploadFilter builds the WHERE clause and args from the non-empty query fields.
// An empty Account means no owner filter (the admin listing).
func uploadFilter(q store.ListUploadsQuery) (string, []any) {
	var clauses []string
	var args []any
	if q.Account != "" {
		clauses = append(clauses, "uploader_account = ?", "uploader_issuer = ?")
		args = append(args, q.Account, q.Issuer)
	}
	if q.ContentType != "" {
		clauses = append(clauses, "content_type = ?")
		args = append(args, q.ContentType)
	}
	if q.Search != "" {
		clauses = append(clauses, "original_filename LIKE '%'||?||'%' COLLATE NOCASE")
		args = append(args, q.Search)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// Usage returns the total bytes currently attributed to account/issuer.
func (s *Store) Usage(ctx context.Context, account, issuer string) (int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(file_size), 0) FROM uploads WHERE uploader_account = ? AND uploader_issuer = ?`,
		account, issuer).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("usage: %w", err)
	}
	return total, nil
}

// CreateKey persists a new API key record.
func (s *Store) CreateKey(ctx context.Context, k store.APIKey) error {
	scopes, err := json.Marshal(coalesce(k.Scopes))
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO api_keys (id, hash, owner_account, owner_issuer, label, scopes, expires_at, last_used_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Hash, k.OwnerAccount, k.OwnerIssuer, k.Label, string(scopes),
		nullUnix(k.ExpiresAt), nullUnix(k.LastUsedAt), k.CreatedAt.Unix())
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}
	return nil
}

const keyColumns = `id, hash, owner_account, owner_issuer, label, scopes, expires_at, last_used_at, created_at`

// ListKeys returns the caller's keys.
func (s *Store) ListKeys(ctx context.Context, account, issuer string) ([]store.APIKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+keyColumns+` FROM api_keys WHERE owner_account = ? AND owner_issuer = ? ORDER BY created_at`,
		account, issuer)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer rows.Close()

	var keys []store.APIKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// ResolveKey looks up a key by its hash for authentication.
func (s *Store) ResolveKey(ctx context.Context, hash string) (store.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+keyColumns+` FROM api_keys WHERE hash = ?`, hash)
	k, err := scanKey(row)
	if err == sql.ErrNoRows {
		return store.APIKey{}, store.ErrNotFound
	}
	if err != nil {
		return store.APIKey{}, fmt.Errorf("resolve key: %w", err)
	}
	return k, nil
}

// RevokeKey deletes a key owned by account/issuer.
func (s *Store) RevokeKey(ctx context.Context, id, account, issuer string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM api_keys WHERE id = ? AND owner_account = ? AND owner_issuer = ?`,
		id, account, issuer)
	if err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}
	return notFoundIfZero(res)
}

// TouchKey records that a key was just used.
func (s *Store) TouchKey(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().Unix(), id)
	if err != nil {
		return fmt.Errorf("touch key: %w", err)
	}
	return nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanKey(sc scanner) (store.APIKey, error) {
	var (
		k        store.APIKey
		scopes   string
		expires  sql.NullInt64
		lastUsed sql.NullInt64
		created  int64
	)
	if err := sc.Scan(&k.ID, &k.Hash, &k.OwnerAccount, &k.OwnerIssuer, &k.Label, &scopes, &expires, &lastUsed, &created); err != nil {
		return store.APIKey{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &k.Scopes); err != nil {
		return store.APIKey{}, fmt.Errorf("decode scopes: %w", err)
	}
	k.ExpiresAt = unixPtr(expires)
	k.LastUsedAt = unixPtr(lastUsed)
	k.CreatedAt = time.Unix(created, 0).UTC()
	return k, nil
}

func scanUpload(sc scanner) (store.Upload, error) {
	var (
		u          store.Upload
		uploadedAt int64
	)
	if err := sc.Scan(&u.ObjectKey, &u.UploaderAccount, &u.UploaderIssuer, &u.FileSize, &u.ContentType, &u.OriginalFilename, &uploadedAt); err != nil {
		return store.Upload{}, err
	}
	u.UploadedAt = time.Unix(uploadedAt, 0).UTC()
	return u, nil
}

func notFoundIfZero(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// nullUnix converts an optional time to a nullable unix timestamp.
func nullUnix(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

// unixPtr converts a nullable unix timestamp back to an optional time.
func unixPtr(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0).UTC()
	return &t
}

func coalesce(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
