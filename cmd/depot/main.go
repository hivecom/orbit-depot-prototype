// Command depot is the Orbit storage gateway: a thin S3/disk policy-and-signing
// authority that sits in front of object storage. It holds the credentials,
// decides who may upload what, signs or proxies the transfer, and gets out of
// the way.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hivecom/orbit-depot/internal/api"
	"github.com/hivecom/orbit-depot/internal/config"
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

	// Step 1 boots the HTTP surface and health check. The storage, auth, store,
	// and limiter seams are constructed and injected here as each one lands.
	srv := api.New(cfg, log, api.Deps{})

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
