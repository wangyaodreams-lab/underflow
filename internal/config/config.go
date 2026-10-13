// Package config loads Underflow server configuration from the environment.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RegistrationMode controls who may create accounts.
type RegistrationMode string

const (
	RegistrationOpen   RegistrationMode = "open"
	RegistrationClosed RegistrationMode = "closed"
	RegistrationInvite RegistrationMode = "invite"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	ListenAddr      string
	DBDriver        string // "sqlite" or "postgres"
	DBDSN           string
	ServerPepper    []byte
	Registration    RegistrationMode
	Argon2Profile   string
	SessionTTL      time.Duration
	TrustedProxies  []string
	LogLevel        string
	TLSCert         string
	TLSKey          string
	Insecure        bool
	MaxRequestBytes int64
	InviteCode      string
}

// Load reads configuration from the environment and resolves the server
// pepper. When the pepper is unset and SQLite is used, a pepper file is
// created next to the database (0600) so that local deployments work out of
// the box without weakening the cloud default.
func Load() (Config, error) {
	c := Config{
		ListenAddr:      env("UF_LISTEN_ADDR", "127.0.0.1:8080"),
		DBDriver:        strings.ToLower(env("UF_DB_DRIVER", "sqlite")),
		DBDSN:           os.Getenv("UF_DB_DSN"),
		Registration:    RegistrationMode(strings.ToLower(env("UF_REGISTRATION", string(RegistrationOpen)))),
		Argon2Profile:   env("UF_ARGON2_PROFILE", "interactive"),
		LogLevel:        env("UF_LOG_LEVEL", "info"),
		TLSCert:         os.Getenv("UF_TLS_CERT"),
		TLSKey:          os.Getenv("UF_TLS_KEY"),
		Insecure:        envBool("UF_INSECURE", false),
		MaxRequestBytes: 8 << 20, // 8 MiB
		InviteCode:      os.Getenv("UF_INVITE_CODE"),
	}
	if c.DBDSN == "" && c.DBDriver == "sqlite" {
		c.DBDSN = "underflow.db"
	}

	ttl, err := time.ParseDuration(env("UF_SESSION_TTL", "12h"))
	if err != nil || ttl <= 0 {
		return c, fmt.Errorf("config: invalid UF_SESSION_TTL: %v", err)
	}
	c.SessionTTL = ttl

	if p := os.Getenv("UF_TRUSTED_PROXIES"); p != "" {
		for _, part := range strings.Split(p, ",") {
			if s := strings.TrimSpace(part); s != "" {
				c.TrustedProxies = append(c.TrustedProxies, s)
			}
		}
	}

	switch c.Registration {
	case RegistrationOpen, RegistrationClosed, RegistrationInvite:
	default:
		return c, fmt.Errorf("config: invalid UF_REGISTRATION %q", c.Registration)
	}
	switch c.Argon2Profile {
	case "interactive", "moderate", "paranoid":
	default:
		return c, fmt.Errorf("config: invalid UF_ARGON2_PROFILE %q", c.Argon2Profile)
	}
	switch c.DBDriver {
	case "sqlite", "postgres":
	default:
		return c, fmt.Errorf("config: invalid UF_DB_DRIVER %q", c.DBDriver)
	}

	pepper, err := resolvePepper(c)
	if err != nil {
		return c, err
	}
	c.ServerPepper = pepper
	return c, nil
}

func resolvePepper(c Config) ([]byte, error) {
	if raw := os.Getenv("UF_SERVER_PEPPER"); raw != "" {
		return decodePepper(raw)
	}
	if c.DBDriver != "sqlite" {
		if c.Insecure {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return nil, err
			}
			return b, nil
		}
		return nil, errors.New("config: UF_SERVER_PEPPER is required for non-sqlite deployments (or set UF_INSECURE=1)")
	}
	path := os.Getenv("UF_SERVER_PEPPER_FILE")
	if path == "" {
		path = c.DBDSN + ".pepper"
	}
	if b, err := os.ReadFile(path); err == nil { // #nosec G304,G703 -- operator-controlled config path.
		return decodePepper(strings.TrimSpace(string(b)))
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700) // #nosec G703 -- operator-controlled config path.
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(b)), 0o600); err != nil { // #nosec G304,G703 -- operator-controlled config path.
		return nil, fmt.Errorf("config: write pepper file: %w", err)
	}
	return b, nil
}

func decodePepper(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := []byte(s)
	if len(b) < 32 {
		return nil, fmt.Errorf("config: server pepper must be at least 32 bytes (got %d)", len(b))
	}
	return b, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
