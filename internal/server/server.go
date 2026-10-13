// Package server wires configuration, storage and the HTTP API into a runnable
// server.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/wangyaodreams-lab/underflow/internal/config"
	"github.com/wangyaodreams-lab/underflow/internal/store"
)

// Server owns the HTTP listener and background maintenance.
type Server struct {
	cfg   config.Config
	store store.Store
	log   *slog.Logger

	httpServer *http.Server
}

// New constructs a Server.
func New(cfg config.Config, st store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, store: st, log: log}
}

// Handler exposes the fully-wired HTTP handler (useful for tests).
func (s *Server) Handler() http.Handler { return s.router() }

// Run starts the listener and blocks until ctx is cancelled or the server
// fails. It performs graceful shutdown.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	s.httpServer = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	maint := make(chan struct{})
	go s.maintain(ctx, maint)

	serveErr := make(chan error, 1)
	go func() {
		if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
			serveErr <- s.httpServer.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			serveErr <- s.httpServer.Serve(ln)
		}
	}()
	s.log.Info("underflow listening", "addr", ln.Addr().String(), "db", s.cfg.DBDriver, "tls", s.cfg.TLSCert != "")

	select {
	case <-ctx.Done():
		close(maint)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.log.Warn("graceful shutdown failed", "error", err)
		}
		return nil
	case err := <-serveErr:
		close(maint)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// maintain periodically prunes expired sessions and rate-limiter buckets.
func (s *Server) maintain(ctx context.Context, done <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()
			if n, err := s.store.DeleteExpiredSessions(ctx, now.UnixNano()); err != nil {
				s.log.Warn("session cleanup failed", "error", err)
			} else if n > 0 {
				s.log.Info("expired sessions removed", "count", n)
			}
		}
	}
}
