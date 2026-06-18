// Command depot is the Orbit storage gateway: a thin S3/disk policy-and-signing
// authority that sits in front of object storage. It holds the credentials,
// decides who may upload what, signs or proxies the transfer, and gets out of
// the way.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hivecom/orbit-depot/internal/api"
	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/place"
	"github.com/hivecom/orbit-depot/internal/quota"
	"github.com/hivecom/orbit-depot/internal/ratelimit"
	"github.com/hivecom/orbit-depot/internal/storage"
	"github.com/hivecom/orbit-depot/internal/storage/fs"
	"github.com/hivecom/orbit-depot/internal/store"
	"github.com/hivecom/orbit-depot/internal/store/sqlite"
)

func main() {
	configPath := flag.String("config", "depot.toml", "path to the TOML config file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(*configPath, log); err != nil {
		log.Error("depot exited", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	driver, err := buildDriver(cfg)
	if err != nil {
		return err
	}

	places, err := buildPlaces(cfg)
	if err != nil {
		return err
	}

	// The store is the system of record for stateful capabilities; it is nil for
	// a pure-anonymous Depot. Quota enforcement and API-key auth read through it,
	// so it is built before the authenticator.
	st, err := buildStore(cfg)
	if err != nil {
		return err
	}
	if st != nil {
		defer st.Close()
	}

	authn, err := buildAuth(context.Background(), cfg, st)
	if err != nil {
		return err
	}
	if cfg.Depot.Credentials.OIDC && cfg.Depot.OIDC.Audience == "" {
		log.Warn("oidc audience not configured; the aud claim is not checked, relying on the issuer as the tenant boundary",
			"issuer", cfg.Depot.OIDC.Issuer)
	}

	// In-memory limiter: correct for the single-box shape. The Redis limiter for
	// horizontal deployments swaps in here once it lands.
	limiter := ratelimit.NewMemory()
	defer limiter.Close()

	srv := api.New(cfg, log, api.Deps{
		Driver:  driver,
		Auth:    authn,
		Places:  places,
		Store:   st,
		Limiter: limiter,
		Quota:   buildQuota(cfg, st),
	})

	httpSrv := &http.Server{
		Addr:              cfg.Depot.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Run the server until a shutdown signal arrives.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Info("depot listening", "addr", cfg.Depot.Listen, "driver", cfg.Depot.Driver)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// buildDriver constructs the storage driver selected in config. Config
// validation has already guaranteed the driver's required fields are present.
func buildDriver(cfg *config.Config) (storage.Driver, error) {
	switch cfg.Depot.Driver {
	case "fs":
		return fs.New(cfg.Depot.FS.Root, cfg.Depot.PublicURL)
	case "s3":
		return nil, fmt.Errorf("s3 driver is not implemented yet")
	default:
		return nil, fmt.Errorf("unknown driver %q", cfg.Depot.Driver)
	}
}

// buildAuth constructs the authenticator from the enabled credential flags. The
// chain routes Bearer tokens to the oidc or api_key verifier by token shape and
// falls back to anonymous when that credential is enabled.
func buildAuth(ctx context.Context, cfg *config.Config, st store.Store) (auth.Authenticator, error) {
	c := cfg.Depot.Credentials

	var oidcAuthn, keyAuthn auth.Authenticator
	if c.OIDC {
		o, err := auth.OIDC(ctx, cfg.Depot.OIDC.Issuer, cfg.Depot.OIDC.Audience)
		if err != nil {
			return nil, fmt.Errorf("build oidc authenticator: %w", err)
		}
		oidcAuthn = o
	}
	if c.APIKey {
		if st == nil {
			// Config validation requires a store for any stateful credential, so
			// this is a defensive guard, not a reachable user error.
			return nil, fmt.Errorf("api_key credential requires a metadata store")
		}
		keyAuthn = auth.APIKey(st)
	}

	// Pure anonymous keeps the trivial authenticator; no token path to compose.
	if oidcAuthn == nil && keyAuthn == nil {
		return auth.Anonymous(), nil
	}
	return auth.Chain(auth.TokenRouter(oidcAuthn, keyAuthn), c.Anonymous), nil
}

// buildStore opens the metadata store when a stateful capability is enabled. It
// returns a nil Store for a pure-anonymous Depot, which runs without one. Config
// validation has already checked the backend and its required fields.
func buildStore(cfg *config.Config) (store.Store, error) {
	if !cfg.Depot.Credentials.Stateful() {
		return nil, nil
	}
	switch cfg.Depot.Store.Backend {
	case "sqlite":
		st, err := sqlite.Open(cfg.Depot.Store.Path)
		if err != nil {
			return nil, fmt.Errorf("open sqlite store: %w", err)
		}
		return st, nil
	case "postgres":
		return nil, fmt.Errorf("postgres store backend is not implemented yet")
	default:
		return nil, fmt.Errorf("unknown store backend %q", cfg.Depot.Store.Backend)
	}
}

// buildQuota constructs the quota enforcer. Without a store there is no usage to
// read and no identity to attribute, so it falls back to the permissive Allow
// (the correct enforcer for anonymous-only Depot).
func buildQuota(cfg *config.Config, st store.Store) quota.Enforcer {
	if st == nil {
		return quota.Allow
	}
	overrides := make(map[string]int64, len(cfg.Depot.QuotaOverrides))
	for account, size := range cfg.Depot.QuotaOverrides {
		overrides[account] = int64(size)
	}
	return quota.New(st, int64(cfg.Depot.Limits.DefaultQuota), overrides)
}

// buildPlaces builds the upload-destination registry from config, translating
// config places into place definitions. The "uploads" catch-all is always
// present.
func buildPlaces(cfg *config.Config) (*place.Registry, error) {
	defs := make(map[string]place.Definition, len(cfg.Depot.Places))
	for name, p := range cfg.Depot.Places {
		defs[name] = place.Definition{
			Prefix:          p.Prefix,
			Strategy:        place.Strategy(p.Key),
			MaxSize:         int64(p.MaxSize),
			AllowedMIME:     p.AllowedMIME,
			RequireIdentity: p.RequireIdentity,
		}
	}
	return place.New(defs, cfg.Depot.DefaultPlace, int64(cfg.Depot.Limits.MaxFileSize))
}
