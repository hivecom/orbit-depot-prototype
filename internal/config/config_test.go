package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validFS returns a minimal valid config: fs driver, anonymous-only, stateless.
func validFS() *Config {
	return &Config{Depot: Depot{
		Driver:      "fs",
		PublicURL:   "https://depot.example.com",
		FS:          FS{Root: "/var/lib/depot"},
		Credentials: Credentials{Anonymous: true},
		Places:      map[string]Place{"uploads": {}},
	}}
}

func TestValidateOK(t *testing.T) {
	cases := map[string]*Config{
		"fs anonymous": validFS(),
		"s3 oidc with sqlite store": {Depot: Depot{
			Driver:      "s3",
			S3:          S3{Endpoint: "s3.example.com", Bucket: "uploads"},
			OIDC:        OIDC{Issuer: "https://id.example.com"},
			Credentials: Credentials{OIDC: true},
			Store:       Store{Backend: "sqlite", Path: "/var/lib/depot/depot.db"},
			Places:      map[string]Place{"uploads": {}},
		}},
		"postgres store with api_key": {Depot: Depot{
			Driver:      "fs",
			PublicURL:   "https://depot.example.com",
			FS:          FS{Root: "/data"},
			Credentials: Credentials{APIKey: true},
			Store:       Store{Backend: "postgres", DSN: "postgres://localhost/depot"},
			Places:      map[string]Place{"uploads": {}},
		}},
		"redis enabled with addr": {Depot: Depot{
			Driver:      "fs",
			PublicURL:   "https://depot.example.com",
			FS:          FS{Root: "/data"},
			Credentials: Credentials{Anonymous: true},
			Redis:       Redis{Enabled: true, Addr: "localhost:6379"},
			Places:      map[string]Place{"uploads": {}},
		}},
		"default place pointing at a configured place": {Depot: Depot{
			Driver:       "fs",
			PublicURL:    "https://depot.example.com",
			DefaultPlace: "uploads",
			FS:           FS{Root: "/data"},
			Credentials:  Credentials{Anonymous: true},
			Places:       map[string]Place{"uploads": {}},
		}},
	}
	for name, cfg := range cases {
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: Validate() = %v, want nil", name, err)
		}
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]func(*Config){
		"unknown driver":    func(c *Config) { c.Depot.Driver = "ftp" },
		"s3 missing bucket": func(c *Config) { c.Depot.Driver = "s3"; c.Depot.S3 = S3{Endpoint: "x"} },
		"fs missing root":   func(c *Config) { c.Depot.FS = FS{} },
		"no credentials":    func(c *Config) { c.Depot.Credentials = Credentials{} },
		"oidc without issuer": func(c *Config) {
			c.Depot.Credentials = Credentials{OIDC: true}
			c.Depot.Store = Store{Backend: "sqlite", Path: "/x"}
		},
		"stateful no store": func(c *Config) { c.Depot.Credentials = Credentials{APIKey: true} },
		"sqlite without path": func(c *Config) {
			c.Depot.Credentials = Credentials{APIKey: true}
			c.Depot.Store = Store{Backend: "sqlite"}
		},
		"postgres without dsn": func(c *Config) {
			c.Depot.Credentials = Credentials{APIKey: true}
			c.Depot.Store = Store{Backend: "postgres"}
		},
		"redis enabled no addr": func(c *Config) { c.Depot.Redis = Redis{Enabled: true} },
		"no places configured":  func(c *Config) { c.Depot.Places = nil },
		"default place not configured": func(c *Config) {
			c.Depot.DefaultPlace = "nope"
		},
	}
	for name, mutate := range cases {
		cfg := validFS()
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want error", name)
		}
	}
}

func TestLoadDefaultsAndStrict(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.toml")
	mustWrite(t, good, `
[depot]
driver = "s3"
default_place = "uploads"
[depot.s3]
endpoint = "s3.example.com"
bucket = "uploads"
[depot.credentials]
anonymous = true
[depot.limits]
max_file_size = "100MB"
rate_limit_per_ip = "30/min"
[depot.places.uploads]
`)
	cfg, err := Load(good)
	if err != nil {
		t.Fatalf("Load(good) = %v", err)
	}
	if cfg.Depot.Listen != defaultListen {
		t.Errorf("default Listen = %q, want %q", cfg.Depot.Listen, defaultListen)
	}
	if cfg.Depot.S3.Region != "auto" {
		t.Errorf("default S3.Region = %q, want \"auto\"", cfg.Depot.S3.Region)
	}
	if cfg.Depot.Limits.MaxFileSize != 100*mb {
		t.Errorf("MaxFileSize = %d, want %d", cfg.Depot.Limits.MaxFileSize, 100*mb)
	}

	bad := filepath.Join(dir, "bad.toml")
	mustWrite(t, bad, `
[depot]
driver = "fs"
bogus = true
[depot.fs]
root = "/x"
[depot.credentials]
anonymous = true
`)
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "parse config") {
		t.Errorf("Load(bad) error = %v, want parse error on unknown field", err)
	}

	if _, err := Load(filepath.Join(dir, "missing.toml")); err == nil {
		t.Error("Load(missing) = nil error, want error")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
