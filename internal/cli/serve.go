package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/config"
	"github.com/wangyaodreams-lab/underflow/internal/server"
	"github.com/wangyaodreams-lab/underflow/internal/store"
	"github.com/wangyaodreams-lab/underflow/internal/store/postgres"
	"github.com/wangyaodreams-lab/underflow/internal/store/sqlite"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the web/API server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd)
		},
	}
	f := cmd.Flags()
	f.String("listen", "", "listen address (default 127.0.0.1:8080)")
	f.String("driver", "", "database driver: sqlite|postgres")
	f.String("dsn", "", "database DSN / file path")
	f.String("registration", "", "registration mode: open|closed|invite")
	f.String("profile", "", "argon2 profile: interactive|moderate|paranoid")
	f.String("session-ttl", "", "session lifetime, e.g. 12h")
	f.String("log-level", "", "log level: debug|info")
	f.String("tls-cert", "", "TLS certificate file")
	f.String("tls-key", "", "TLS key file")
	f.Bool("local", false, "local single-user mode (bind loopback, registration closed)")
	f.Bool("insecure", false, "allow running without a server pepper (NOT for production)")
	return cmd
}

func runServe(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if v := getFlag(cmd, "listen"); v != "" {
		cfg.ListenAddr = v
	}
	if v := getFlag(cmd, "driver"); v != "" {
		cfg.DBDriver = v
	}
	if v := getFlag(cmd, "dsn"); v != "" {
		cfg.DBDSN = expandPath(v)
	}
	if v := getFlag(cmd, "registration"); v != "" {
		cfg.Registration = config.RegistrationMode(v)
	}
	if v := getFlag(cmd, "profile"); v != "" {
		switch crypto.Profile(strings.ToLower(v)) {
		case crypto.ProfileInteractive, crypto.ProfileModerate, crypto.ProfileParanoid:
			cfg.Argon2Profile = strings.ToLower(v)
		default:
			return fmt.Errorf("invalid --profile %q: use interactive, moderate or paranoid", v)
		}
	}
	if v := getFlag(cmd, "session-ttl"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil || ttl <= 0 {
			return fmt.Errorf("invalid --session-ttl %q: use a positive duration such as 12h", v)
		}
		cfg.SessionTTL = ttl
	}
	if v := getFlag(cmd, "log-level"); v != "" {
		cfg.LogLevel = strings.ToLower(v)
	}
	if v := getFlag(cmd, "tls-cert"); v != "" {
		cfg.TLSCert = expandPath(v)
	}
	if v := getFlag(cmd, "tls-key"); v != "" {
		cfg.TLSKey = expandPath(v)
	}
	if getBool(cmd, "local") {
		cfg.Registration = config.RegistrationClosed
		// Only redirect the listener when the address was left unset. An
		// explicit --listen flag or UF_LISTEN_ADDR must win, otherwise the
		// documented environment-variable configuration silently binds the
		// wrong port.
		if getFlag(cmd, "listen") == "" && os.Getenv("UF_LISTEN_ADDR") == "" {
			cfg.ListenAddr = "127.0.0.1:8080"
		}
	}
	if getBool(cmd, "insecure") {
		cfg.Insecure = true
	}

	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	if cfg.ServerPepper == nil {
		return fmt.Errorf("server pepper is required (set UF_SERVER_PEPPER)")
	}
	srv := server.New(cfg, st, log)
	return srv.Run(ctx)
}

func openStore(ctx context.Context, cfg config.Config) (store.Store, error) {
	switch cfg.DBDriver {
	case "postgres":
		return postgres.Open(ctx, postgres.Options{DSN: cfg.DBDSN})
	case "sqlite":
		return sqlite.Open(ctx, sqlite.Options{Path: cfg.DBDSN})
	default:
		return nil, fmt.Errorf("unknown database driver %q", cfg.DBDriver)
	}
}
