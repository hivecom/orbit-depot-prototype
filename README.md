# orbit-depot

Thin S3/FS media abstraction layer for Orbit.

Depot is a thin storage policy-and-signing gateway. It holds the storage
credentials, decides who may upload what, signs (or proxies) the transfer, and
gets out of the way. It is not an app and has no UI; the Orbit client is the UI.

See the [Depot spec](https://github.com/hivecom/orbit-spec/blob/main/spec/02-components/03-depot.md)
for the full design.

## Layout

Depot composes a few seams. Each is a small interface with swappable
implementations selected at boot from config:

| Seam | Package | What it abstracts | Implementations |
|------|---------|-------------------|-----------------|
| Driver | `internal/storage` | Where bytes live | `fs` (proxied to disk), `s3` (planned) |
| Authenticator | `internal/auth` | Who is calling | `anonymous`, `oidc` (JWKS), `api_key` |
| Place | `internal/place` | Where an upload lands and on what terms | configured destinations + key strategies |
| Store | `internal/store` | Durable metadata (uploads, quota, keys) | `sqlite`, `postgres` (planned) |
| Limiter | `internal/ratelimit` | Rate limiting | in-memory, `redis` (planned) |
| Quota | `internal/quota` | Per-user storage limits | default + per-account overrides |

The client never names the object key: it names a *place*, and Depot derives the
key from the verified identity, so a caller can only write within its own
namespace. See the spec's Object Key Structure for the scheme.

Two deployment shapes:

- **Single box / homelab**: `fs` + sqlite + in-memory limiter. No Redis, no Postgres.
- **Scale**: `s3` + postgres + redis. Stateless instances behind a load balancer. (`s3`/`postgres`/`redis` are planned.)

The toggles compose; nothing is paid for unless enabled. A pure-`anonymous`
Depot runs fully stateless (no store).

## API

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Gateway health |
| `POST /upload/presign` | Authenticate, validate, rate-limit, return a time-limited upload URL |
| `POST /upload` | One-shot multipart upload (ShareX/cURL); proxies bytes, throttled harder |
| `POST /keys`, `GET /keys`, `DELETE /keys/{id}` | Mint, list, revoke API keys (requires OIDC) |
| `DELETE /file/{key}` | Delete a file you uploaded (requires identity) |
| `GET /quota` | Report your current usage and limit |
| `PUT/GET /transfer/{key}` | fs driver only: proxied upload / download |

## Running

```sh
cp depot.example.toml depot.toml   # then edit (driver, credentials, places)
go run ./cmd/depot -config depot.toml
```

Or with Docker (fs driver, data in a named volume):

```sh
docker compose up --build          # serves on :3000
```

## Status

Working today: the `fs` driver, all three credential types (`anonymous`, `oidc`,
`api_key`), the place registry, the sqlite store, quota enforcement, in-memory
rate limiting, CORS, and the full endpoint surface above.

Planned: the `s3` driver, the `postgres` store, and the `redis` limiter (each
errors clearly at boot if selected today), plus recipient-scoped private
downloads (NEXT in the spec).

## License

[AGPL-3.0](LICENSE).
