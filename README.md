# orbit-depot-prototype

Depot is a thin storage policy-and-signing gateway. It holds the storage credentials, decides who may upload what, signs (or proxies) the transfer, and gets out of the way. It is not an app and has no UI; the Orbit client is the UI.

> [!NOTE] 
> This is a prototype of Orbit's thin S3/FS media abstraction layer. It serves as a proof-of-concept today where we can iterate quickly and discover the right abstractions. Once the design settles and is proven, it will be adjusted in the spec and reimplemented in Rust for production use.
>
> This means that it does not cover all the capabilities of the specification. Notably, the `s3` driver is not implemented yet, and the `postgres` store and `redis` limiter are planned but not implemented. The `fs` driver and `sqlite` store are implemented and work for local testing.

See the [Depot spec](https://github.com/hivecom/orbit-spec/blob/main/spec/02-components/03-depot.md)
for the full design.

## Layout

Depot composes a few seams. Each is a small interface with swappable implementations selected at boot from config:

| Seam | Package | What it abstracts | Implementations |
|------|---------|-------------------|-----------------|
| Driver | `internal/storage` | Where bytes live | `fs` (proxied to disk), `s3` (planned) |
| Authenticator | `internal/auth` | Who is calling | `anonymous`, `oidc` (JWKS), `api_key` |
| Place | `internal/place` | Where an upload lands and on what terms | configured destinations + key strategies |
| Store | `internal/store` | Durable metadata (uploads, quota, keys) | `sqlite`, `postgres` (planned) |
| Limiter | `internal/ratelimit` | Rate limiting | in-memory, `redis` (planned) |
| Quota | `internal/quota` | Per-user storage limits | default + per-account overrides |

The client never names the object key: it names a *place*, and Depot derives the key from the verified identity, so a caller can only write within its own namespace. See the spec's Object Key Structure for the scheme.

Two deployment shapes:

- **Single box / homelab**: `fs` + sqlite + in-memory limiter. No Redis, no Postgres.
- **Scale**: `s3` + postgres + redis. Stateless instances behind a load balancer. (`s3`/`postgres`/`redis` are planned.)

The toggles compose; nothing is paid for unless enabled. A pure-`anonymous` Depot runs fully stateless (no store).

## API

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Configured `index_file` HTML, or a plaintext summary with project links |
| `GET /health` | Gateway health |
| `POST /upload/presign` | Authenticate, validate, rate-limit, return a time-limited upload URL |
| `POST /upload` | One-shot multipart upload (ShareX/cURL); proxies bytes, throttled harder |
| `POST /keys`, `GET /keys`, `DELETE /keys/{id}` | Mint, list, revoke API keys (requires OIDC) |
| `GET /files` | List your own uploads, paged/sorted/searchable (requires identity) |
| `DELETE /files` | Wipe all of your own uploads; returns the count removed (requires identity) |
| `GET /admin/files` | List uploads across all owners (requires an OIDC admin claim) |
| `DELETE /admin/files?account=` | Wipe all uploads owned by one user (`account` required, `issuer` optional); returns the count removed (requires an OIDC admin claim) |
| `GET /admin/metrics` | Aggregate upload counts and size, same filters as `/admin/files` (requires an OIDC admin claim) |
| `GET /admin/users` | Uploaders ranked by total bytes or upload count, with per-user file count (requires an OIDC admin claim) |
| `GET /admin/content-types` | Distinct content types across all uploads, for the file-type filter (requires an OIDC admin claim) |
| `DELETE /file/{key}` | Delete a file you uploaded; an admin may delete any file (requires identity) |
| `GET /quota` | Report your current usage and limit |
| `PUT/GET /transfer/{key}` | `fs` driver only: proxied upload / download |

## Running

```sh
cp depot.example.toml depot.toml # then edit (driver, credentials, places)
go run ./cmd/depot -config depot.toml
```

Or with Docker (fs driver, data in a named volume):

```sh
docker compose up --build # serves on :3000
```

### Behind a reverse proxy

Run Depot behind a TLS-terminating reverse proxy. Under the `fs` driver, Depot proxies every transfer through itself, so downloads (`GET /transfer/<key>`) are the hot path and reads amplify hard (one upload is fetched by everyone who opens the channel). Those downloads are public, unsigned, and immutable (keys are unique), so they cache effectively forever. Cache them at the proxy to keep read amplification off the backend disk.

[`system/nginx/depot.conf`](system/nginx/depot.conf) is a commented nginx example that does exactly this: caches `/transfer/` on local disk with stampede protection, while leaving the dynamic routes (presign, upload, keys, quota) uncached. The `s3` driver doesn't need it - there the client transfers directly with the object store, so cache at the bucket / CDN layer instead.

## License

[AGPL-3.0](LICENSE).
