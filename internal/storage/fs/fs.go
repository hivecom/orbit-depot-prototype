// Package fs implements the storage Driver over a local filesystem. There is no
// presigned-URL equivalent for local disk, so the fs driver proxies transfers:
// PresignUpload hands back a Depot-hosted URL carrying a signed capability, and
// the client PUTs through Depot (UploadHandler), which writes to disk. Downloads
// are served by Depot too. This makes the fs driver single-box by nature.
//
// The client API contract is identical to the s3 driver: the client presigns,
// then transfers to whatever URL it gets back.
package fs

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/hivecom/orbit-depot/internal/storage"
)

// Errors describing why a capability or key was rejected.
var (
	errBadCapability = errors.New("malformed upload capability")
	errBadSignature  = errors.New("invalid upload signature")
	errExpired       = errors.New("upload capability expired")
	errInvalidKey    = errors.New("invalid object key")
)

// transferPrefix is the URL path under which proxied transfers are mounted. It
// must match the routes registered in the api package.
const transferPrefix = "/transfer/"

// Driver stores and serves objects on local disk.
type Driver struct {
	root   string   // absolute, cleaned filesystem root
	base   *url.URL // Depot's public base URL
	secret []byte   // per-process HMAC key for upload capabilities
}

// New creates an fs driver rooted at root, building transfer URLs against
// publicURL (Depot's externally reachable base URL).
func New(root, publicURL string) (*Driver, error) {
	if root == "" {
		return nil, errors.New("fs driver: empty root")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, err
	}

	base, err := url.Parse(strings.TrimRight(publicURL, "/"))
	if err != nil {
		return nil, err
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, errors.New("fs driver: public_url must be an absolute URL")
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	return &Driver{root: abs, base: base, secret: secret}, nil
}

// PresignUpload returns a Depot-hosted upload URL carrying a signed capability.
func (d *Driver) PresignUpload(_ context.Context, key string, c storage.Constraints) (storage.UploadTarget, error) {
	if err := validateKey(key); err != nil {
		return storage.UploadTarget{}, err
	}
	expires := time.Now().Add(c.Expiry)
	q := d.signUpload(uploadCap{key: key, maxSize: c.MaxSize, contentType: c.ContentType, expires: expires})

	u := *d.base
	u.Path = path.Join(u.Path, transferPrefix, key)
	u.RawQuery = q.Encode()

	return storage.UploadTarget{
		URL:       u.String(),
		Method:    http.MethodPut,
		ObjectKey: key,
		ExpiresIn: int(time.Until(expires).Seconds()),
	}, nil
}

// ResolveDownload returns the Depot-hosted URL that serves the object.
func (d *Driver) ResolveDownload(_ context.Context, key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	u := *d.base
	u.Path = path.Join(u.Path, transferPrefix, key)
	return u.String(), nil
}

// diskPath maps an object key to a filesystem path, guaranteed to stay within
// root. Cleaning against a leading slash collapses any "../" so traversal
// cannot escape the root.
func (d *Driver) diskPath(key string) (string, error) {
	clean := path.Clean("/" + key)
	if clean == "/" {
		return "", errInvalidKey
	}
	p := filepath.Join(d.root, filepath.FromSlash(clean))
	if p != d.root && !strings.HasPrefix(p, d.root+string(os.PathSeparator)) {
		return "", errInvalidKey
	}
	return p, nil
}

// validateKey rejects keys that are empty, absolute, or contain traversal
// segments, before they ever reach the filesystem.
func validateKey(key string) error {
	if key == "" || strings.HasPrefix(key, "/") {
		return errInvalidKey
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errInvalidKey
		}
	}
	return nil
}
