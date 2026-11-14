package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Ammarmyp/payrail/internal/auth"
	"github.com/Ammarmyp/payrail/internal/config"
	"github.com/Ammarmyp/payrail/internal/platform/database"
	"github.com/Ammarmyp/payrail/internal/platform/httpx"
	"github.com/Ammarmyp/payrail/internal/platform/logger"
	"github.com/Ammarmyp/payrail/internal/user"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := logger.New(cfg.Env)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer pool.Close()

	userStore := user.NewPostgresStore(pool)
	refreshStore := auth.NewPostgresRefreshStore(pool)
	signer := auth.NewTokenSigner(cfg.JWTSecret, cfg.AccessTTL)
	authSvc := auth.NewService(userStore, refreshStore, signer, cfg.RefreshTTL, cfg.BcryptCost)
	authHandler := auth.NewHandler(authSvc, cfg.Env)

	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)

	r.Get("/healthz", httpx.Healthz())
	r.Get("/readyz", httpx.Readyz(map[string]httpx.Pinger{
		"postgres": pool,
	}))

	r.Route("/v1/auth", func(r chi.Router) {
		authHandler.Routes(r)
	})
	r.With(auth.RequireAuth(signer)).Get("/v1/me", authHandler.Me)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", cfg.Addr, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server failed: %w", err)
	case <-ctx.Done():
		log.Info("Shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	log.Info("Server stopped cleanly")
	return nil
}
