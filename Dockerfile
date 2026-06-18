# Build a fully static binary (CGO disabled; modernc sqlite and everything else
# are pure Go), then ship it on distroless. No shell, no package manager, just
# the binary and CA certs for outbound TLS (OIDC JWKS, S3 backends).
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /depot ./cmd/depot

# Pre-create the data directory owned by the nonroot user (uid 65532). A fresh
# Docker named volume mounted here inherits this ownership, so the nonroot
# process can write to the fs driver's root.
RUN mkdir -p /data

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /depot /depot
COPY --from=build --chown=65532:65532 /data /data

EXPOSE 3000

ENTRYPOINT ["/depot"]
CMD ["-config", "/etc/depot/depot.toml"]
