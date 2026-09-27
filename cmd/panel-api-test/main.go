package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/api"
	"github.com/FuzzySpace/GlassGamePanel/internal/config"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	srv, err := api.New(cfg)
	if err != nil {
		log.Fatalf("api: %v", err)
	}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if config.UnderlayBind(cfg.ListenAddr) {
		log.Printf("underlay bind %s — CT316 only; do not publish public DNS; gateway allowlist stays in front", cfg.ListenAddr)
	}
	log.Printf("panel-api-test listening %s env=%s aud=%s iss=%s auth=%s jwks_host=%q executor=%s wings_allowlist=%d wings_dial_configured=%t create_nodes=%s alloc_pool=%s deny_sha256=%s mutate_rpm=%d read_rpm=%d migrate_mode_max=%s migrate_disabled=%t ptero_source_configured=%t",
		cfg.ListenAddr, cfg.Env, cfg.JWTAud, cfg.JWTIss, cfg.AuthMode(), cfg.JWKSHost(), cfg.WingsExecutor, cfg.WingsAllowlist.Len(), cfg.WingsBaseURL != "" && cfg.WingsToken != "", strings.Join(cfg.CreateNodeAllowlist, ","), cfg.AllocPool, srv.DenySHA256(), cfg.MutateRPM, cfg.ReadRPM, cfg.MigrateModeMax, cfg.MigrateDisabled, cfg.PteroSourceAPIURL != "")

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdown); err != nil {
			log.Printf("shutdown: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}
	os.Exit(0)
}
