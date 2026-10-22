package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/utah-dnr/utah-gcp-common-authz/internal/api"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authn"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authz"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/config"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := db.NewPostgresStore(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to Cloud SQL PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	oidcVerifier := authn.NewMultiIssuerOIDCVerifier(store)
	tokenSvc, err := authn.NewTokenService(
		store,
		oidcVerifier,
		cfg.IssuerURL,
		cfg.SigningKeyID,
		cfg.SigningKeyPEM,
	)
	if err != nil {
		slog.Error("failed to initialize token service", "error", err)
		os.Exit(1)
	}

	pdp := authz.NewPDP(store)
	srv := api.NewServer(store, tokenSvc, pdp, cfg.AdminBootstrapKey)

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("starting Utah Common AuthN/AuthZ Zero Trust server",
			"port", cfg.Port,
			"environment", cfg.Environment,
			"issuer", cfg.IssuerURL,
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down server gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
}
