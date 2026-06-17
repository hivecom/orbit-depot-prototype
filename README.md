# orbit-depot

Thin S3/FS media abstraction layer for Orbit.

Depot is a thin storage policy-and-signing gateway. It holds the storage
credentials, decides who may upload what, signs (or proxies) the transfer, and
gets out of the way. It is not an app and has no UI; the Orbit client is the UI.

See the [Depot spec](https://github.com/hivecom/orbit-spec/blob/main/spec/02-components/03-depot.md)
for the full design.

## Layout

Depot composes four seams. Each is a small interface with swappable
implementations selected at boot from config:

| Seam | Package | What it abstracts |
|------|---------|-------------------|
| Driver | `internal/storage` | Where bytes live: `s3` (presigned, bypasses Depot) or `fs` (proxied to disk) |
| Authenticator | `internal/auth` | Who is calling: `anonymous`, `oidc` (JWKS), `api_key` |
| Store | `internal/store` | Durable metadata (uploads, quota, API keys): sqlite or postgres |
| Limiter | `internal/ratelimit` | Rate limiting: in-memory (single box) or redis (horizontal) |

Two deployment shapes:

- **Single box / homelab**: `fs` + sqlite + in-memory limiter. No Redis, no Postgres.
- **Scale**: `s3` + postgres + redis. Stateless instances behind a load balancer.

The toggles compose; nothing is paid for unless enabled. A pure-`anonymous`
Depot runs fully stateless (no store).

## Running

```sh
cp depot.example.toml depot.toml   # then edit
go run ./cmd/depot -config depot.toml
```

`GET /health` reports gateway status. The rest of the API surface is routed but
returns `501` until each capability is implemented.

## License

[AGPL-3.0](LICENSE).
