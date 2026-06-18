// Package config defines Depot's configuration tree and how it is loaded and
// validated from a TOML file.
//
// The configuration mirrors the two orthogonal axes from the spec: the storage
// driver (where bytes live) and the accepted credentials (who may call). Both
// are composed by the operator; nothing is paid for unless it is enabled.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config is the full Depot configuration. The TOML file nests everything under
// a [depot] table, so the top-level document is a struct with a single field.
type Config struct {
	Depot Depot `toml:"depot"`
}

// Depot holds the gateway configuration.
type Depot struct {
	// Listen is the address the HTTP server binds to (e.g. ":3000").
	Listen string `toml:"listen"`

	// Driver selects where bytes live: "s3" or "fs".
	Driver string `toml:"driver"`

	// PublicURL is Depot's externally reachable base URL, e.g.
	// "https://depot.example.com". The fs driver needs it to build upload and
	// download URLs that point back at Depot.
	PublicURL string `toml:"public_url"`

	// DefaultPlace names the place used when a presign request omits one. It is
	// optional: leave it unset to require every request to name a place. There
	// is no built-in default place.
	DefaultPlace string `toml:"default_place"`

	S3          S3          `toml:"s3"`
	FS          FS          `toml:"fs"`
	OIDC        OIDC        `toml:"oidc"`
	Credentials Credentials `toml:"credentials"`
	Limits      Limits      `toml:"limits"`
	Store       Store       `toml:"store"`
	Redis       Redis       `toml:"redis"`

	// QuotaOverrides maps an account name to a per-user storage limit that
	// replaces the default for that account.
	QuotaOverrides map[string]ByteSize `toml:"quota_overrides"`

	// Places are the named upload destinations. Every destination is configured
	// here, including any permissive catch-all; there is no built-in default
	// place. Each carries its own restrictions (MIME, size) and key strategy.
	// An implementing app points content at a place by name.
	Places map[string]Place `toml:"places"`
}

// Place is a named upload destination with its own policy. A permissive place
// (no MIME restriction, dump strategy) acts as a catch-all; restricted places
// add rules for specific content classes (avatars, banners, ...).
type Place struct {
	// Prefix is the object-key prefix bytes land under, e.g.
	// "orbit/user-content/avatars".
	Prefix string `toml:"prefix"`
	// Key selects the key strategy: "dump" (random per upload, the default) or
	// "account" (deterministic per account, so a re-upload overwrites).
	Key string `toml:"key"`
	// MaxSize caps uploads to this place; 0 falls back to limits.max_file_size.
	MaxSize ByteSize `toml:"max_size"`
	// AllowedMIME whitelists content types; empty means any.
	AllowedMIME []string `toml:"allowed_mime"`
	// RequireIdentity rejects anonymous uploads to this place.
	RequireIdentity bool `toml:"require_identity"`
}

// S3 configures the s3 storage driver. Any S3-compatible backend works
// (MinIO, R2, B2, Garage, Ceph, AWS S3); Depot does not bind to a vendor.
type S3 struct {
	Endpoint  string `toml:"endpoint"`
	Bucket    string `toml:"bucket"`
	Region    string `toml:"region"`
	AccessKey string `toml:"access_key"`
	SecretKey string `toml:"secret_key"`
	// UseSSL controls whether the backend is addressed over HTTPS.
	UseSSL *bool `toml:"use_ssl"`
}

// FS configures the fs storage driver (local disk). Depot proxies transfers
// itself under this driver, which makes it single-box by nature.
type FS struct {
	Root string `toml:"root"`
}

// OIDC configures JWT verification. Required when credentials.oidc is enabled.
// Depot verifies tokens against the provider's published JWKS; it never calls
// another Orbit component to check identity.
type OIDC struct {
	Issuer   string `toml:"issuer"`
	Audience string `toml:"audience"`
}

// Credentials is the set of capability flags the operator toggles, in any
// combination. There is no exclusive "open vs OIDC" mode.
type Credentials struct {
	Anonymous bool `toml:"anonymous"`
	OIDC      bool `toml:"oidc"`
	APIKey    bool `toml:"api_key"`
}

// Stateful reports whether any enabled capability needs the metadata store.
// Pure-anonymous signing is stateless; everything else (quotas, deletion,
// audit, API keys) needs durable state.
func (c Credentials) Stateful() bool {
	return c.OIDC || c.APIKey
}

// Any reports whether at least one credential is enabled.
func (c Credentials) Any() bool {
	return c.Anonymous || c.OIDC || c.APIKey
}

// Limits holds size, quota, and rate-limit configuration.
type Limits struct {
	MaxFileSize ByteSize `toml:"max_file_size"`
	// DefaultQuota is the per-user storage limit applied unless overridden.
	DefaultQuota     ByteSize `toml:"default_quota"`
	RateLimitPerIP   Rate     `toml:"rate_limit_per_ip"`
	RateLimitPerUser Rate     `toml:"rate_limit_per_user"`
	// OneshotRateLimit throttles POST /upload, which proxies bytes even under
	// the s3 driver and so is throttled harder than the presign flow.
	OneshotRateLimit Rate `toml:"oneshot_rate_limit"`
}

// Store configures the metadata database. Only consulted when a stateful
// capability is enabled.
type Store struct {
	Backend string `toml:"backend"` // "sqlite" | "postgres"
	Path    string `toml:"path"`    // sqlite file path
	DSN     string `toml:"dsn"`     // postgres connection string
}

// Redis configures the optional distributed coordination backend. When
// enabled, rate limiting is shared across instances so Depot scales
// horizontally behind a load balancer (the s3 + postgres + redis shape).
// When disabled, rate limiting is in-memory and single-instance.
//
// Redis is a coordination layer, not a system of record. Durable accounting
// (quotas, uploads, API keys) stays in the metadata store.
type Redis struct {
	Enabled  bool     `toml:"enabled"`
	Addr     string   `toml:"addr"`
	Addrs    []string `toml:"addrs"` // cluster mode; takes precedence over Addr
	Password string   `toml:"password"`
	DB       int      `toml:"db"`
}

const defaultListen = ":3000"

// Load reads, decodes, applies defaults to, and validates the config file at
// path. A returned error means Depot should not start.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Depot.Listen == "" {
		c.Depot.Listen = defaultListen
	}
	if c.Depot.Driver == "s3" && c.Depot.S3.Region == "" {
		c.Depot.S3.Region = "auto"
	}
}

// Validate checks the loaded configuration for internal consistency. It only
// validates the fields step-1 wiring depends on; per-capability validation
// grows alongside each capability.
func (c *Config) Validate() error {
	d := c.Depot

	switch d.Driver {
	case "s3":
		if d.S3.Endpoint == "" || d.S3.Bucket == "" {
			return errors.New("driver = \"s3\" requires depot.s3.endpoint and depot.s3.bucket")
		}
	case "fs":
		if d.FS.Root == "" {
			return errors.New("driver = \"fs\" requires depot.fs.root")
		}
		if d.PublicURL == "" {
			return errors.New("driver = \"fs\" requires depot.public_url")
		}
	default:
		return fmt.Errorf("driver must be \"s3\" or \"fs\", got %q", d.Driver)
	}

	if !d.Credentials.Any() {
		return errors.New("at least one credential must be enabled (anonymous, oidc, api_key)")
	}
	if d.Credentials.OIDC && d.OIDC.Issuer == "" {
		return errors.New("credentials.oidc requires depot.oidc.issuer")
	}

	if d.Credentials.Stateful() {
		switch d.Store.Backend {
		case "sqlite":
			if d.Store.Path == "" {
				return errors.New("store.backend = \"sqlite\" requires depot.store.path")
			}
		case "postgres":
			if d.Store.DSN == "" {
				return errors.New("store.backend = \"postgres\" requires depot.store.dsn")
			}
		default:
			return fmt.Errorf("a stateful credential is enabled, so store.backend must be \"sqlite\" or \"postgres\", got %q", d.Store.Backend)
		}
	}

	if d.Redis.Enabled && d.Redis.Addr == "" && len(d.Redis.Addrs) == 0 {
		return errors.New("redis.enabled requires depot.redis.addr or depot.redis.addrs")
	}

	if len(d.Places) == 0 {
		return errors.New("at least one upload destination must be configured under [depot.places]")
	}
	if d.DefaultPlace != "" {
		if _, ok := d.Places[d.DefaultPlace]; !ok {
			return fmt.Errorf("default_place %q is not a configured place", d.DefaultPlace)
		}
	}

	return nil
}
