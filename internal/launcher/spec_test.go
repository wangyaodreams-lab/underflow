package launcher

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testAddr returns a loopback address that is free right now.
func testAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

func baseSpec(t *testing.T) Spec {
	t.Helper()
	s := DefaultSpec(t.TempDir())
	s.Listen = testAddr(t)
	return s
}

func TestDeriveMapsEnvironment(t *testing.T) {
	s := baseSpec(t)
	s.DBDSN = "underflow.db"
	s.SessionTTL = "8h"
	s.LogLevel = "debug"
	s.Registration = "invite"
	s.InviteCode = "let-me-in"
	s.Argon2Profile = "moderate"
	s.TrustedProxies = "127.0.0.1"

	res := s.Derive("underflow")
	if !res.Ready {
		t.Fatalf("expected a ready spec, got issues: %+v", res.Issues)
	}
	want := map[string]string{
		"UF_LISTEN_ADDR":        s.Listen,
		"UF_DB_DRIVER":          "sqlite",
		"UF_DB_DSN":             filepath.Join(s.dir, "underflow.db"),
		"UF_REGISTRATION":       "invite",
		"UF_INVITE_CODE":        "let-me-in",
		"UF_ARGON2_PROFILE":     "moderate",
		"UF_SESSION_TTL":        "8h",
		"UF_LOG_LEVEL":          "debug",
		"UF_TRUSTED_PROXIES":    "127.0.0.1",
		"UF_SERVER_PEPPER_FILE": filepath.Join(s.dir, "underflow.db.pepper"),
	}
	for k, v := range want {
		if got := res.Env[k]; got != v {
			t.Errorf("env %s = %q, want %q", k, got, v)
		}
	}
	if _, ok := res.Env["UF_INSECURE"]; ok {
		t.Error("UF_INSECURE must be absent when insecure mode is off")
	}
	if len(res.Args) != 2 || res.Args[0] != "serve" || res.Args[1] != "--local" {
		t.Errorf("args = %v, want [serve --local]", res.Args)
	}
	if !strings.Contains(res.Command, "serve --local") {
		t.Errorf("command %q should contain the serve invocation", res.Command)
	}
	if strings.Contains(res.Command, "let-me-in") {
		t.Error("the rendered command must not leak the invite code")
	}
	if !strings.Contains(res.Command, "UF_INVITE_CODE=REDACTED") {
		t.Error("the rendered command should show the invite code as redacted")
	}
}

// A PostgreSQL DSN is a connection string, not a file path: resolving it
// against the working directory corrupts it.
func TestDeriveLeavesPostgresDSNAlone(t *testing.T) {
	s := baseSpec(t)
	s.DBDriver = "postgres"
	const dsn = "postgres://underflow:secret@localhost:5432/underflow?sslmode=disable"
	s.DBDSN = dsn
	s.PepperFilePath = "pepper.txt"

	res := s.Derive("underflow")
	if !res.Ready {
		t.Fatalf("expected a ready spec, got issues: %+v", res.Issues)
	}
	if got := res.Env["UF_DB_DSN"]; got != dsn {
		t.Errorf("UF_DB_DSN = %q, want the connection string unchanged", got)
	}
	if got, want := res.Env["UF_SERVER_PEPPER_FILE"], filepath.Join(s.dir, "pepper.txt"); got != want {
		t.Errorf("UF_SERVER_PEPPER_FILE = %q, want %q", got, want)
	}
}

func TestInsecureSetsEnvironment(t *testing.T) {
	s := baseSpec(t)
	s.Insecure = true
	if got := s.Derive("underflow").Env["UF_INSECURE"]; got != "1" {
		t.Errorf("UF_INSECURE = %q, want \"1\"", got)
	}
}

// `--local` must not silently move the listener away from the port the user
// chose, otherwise the launcher would probe an address nothing listens on.
func TestDeriveKeepsExplicitListenInLocalMode(t *testing.T) {
	s := baseSpec(t)
	s.Local = true
	s.Listen = "127.0.0.1:18080"
	res := s.Derive("underflow")
	if got := res.Env["UF_LISTEN_ADDR"]; got != "127.0.0.1:18080" {
		t.Errorf("UF_LISTEN_ADDR = %q, want the explicit address", got)
	}
	if res.URL != "http://127.0.0.1:18080" {
		t.Errorf("url = %q", res.URL)
	}
	if res.ProbeURL != "http://127.0.0.1:18080/api/v1/healthz" {
		t.Errorf("probeUrl = %q", res.ProbeURL)
	}
}

func TestLocalModeDefaultsTo8080(t *testing.T) {
	s := DefaultSpec(t.TempDir())
	if got := s.EffectiveListen(); got != "127.0.0.1:8080" {
		t.Errorf("EffectiveListen = %q, want 127.0.0.1:8080", got)
	}
}

func TestWildcardListenBecomesBrowsable(t *testing.T) {
	s := baseSpec(t)
	s.Listen = "0.0.0.0:19000"
	res := s.Derive("underflow")
	if res.URL != "http://127.0.0.1:19000" {
		t.Errorf("url = %q, want a loopback address a browser can open", res.URL)
	}
	if !isLoopbackListen("127.0.0.1:1") || isLoopbackListen("0.0.0.0:1") {
		t.Error("isLoopbackListen misclassifies addresses")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	s := baseSpec(t)
	s.DBDriver = "mysql"
	s.SessionTTL = "banana"
	s.Registration = "invite"
	s.TLSCert = "cert.pem"

	issues := s.Validate()
	for _, field := range []string{"dbDsn", "sessionTtl", "inviteCode", "tlsKey", "tlsCert"} {
		if !hasIssue(issues, field) {
			t.Errorf("expected an issue for %q, got %+v", field, issues)
		}
	}
	if !HasErrors(issues) {
		t.Error("HasErrors should report blocking problems")
	}
}

func TestValidateWarnsInsteadOfBlocking(t *testing.T) {
	s := baseSpec(t)
	s.DBDriver = "postgres"
	s.DBDSN = "postgres://u:p@localhost:5432/uf"
	s.Insecure = true
	s.PepperFilePath = "pepper.txt"
	s.Pepper = PepperGenerated

	issues := s.Validate()
	if HasErrors(issues) {
		t.Errorf("insecure postgres should warn, not block: %+v", issues)
	}
	if !hasIssue(issues, "insecure") {
		t.Errorf("expected an insecure-mode warning, got %+v", issues)
	}
}

func TestValidateFlagsBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	s := DefaultSpec(t.TempDir())
	s.Listen = ln.Addr().String()
	issues := s.Validate()
	if !hasIssue(issues, "listen") {
		t.Errorf("expected a listen conflict for %s, got %+v", s.Listen, issues)
	}
}

func TestGeneratePepperWritesOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "server.pepper")

	st, err := GeneratePepper(path, false)
	if err != nil {
		t.Fatalf("GeneratePepper: %v", err)
	}
	if !st.Exists || st.Size != 64 {
		t.Fatalf("pepper status = %+v, want a 64-byte hex pepper", st)
	}
	if st.Fingerprint == "" {
		t.Error("a fingerprint should be reported for an existing pepper")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pepper: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("pepper permissions = %o, want 600", perm)
		}
	}

	// A second call must refuse to clobber the existing pepper...
	if _, err := GeneratePepper(path, false); err == nil {
		t.Error("expected an error when the pepper already exists")
	}
	// ...and must replace it when overwrite is requested.
	if _, err := GeneratePepper(path, true); err != nil {
		t.Errorf("overwrite: %v", err)
	}
}

func TestInspectPepperReportsMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pepper")
	if st := InspectPepper(path); st.Exists {
		t.Error("a missing pepper must not be reported as existing")
	}
	if st := InspectPepper(""); st.ReadError == "" {
		t.Error("an empty path should be explained")
	}
}

func TestNormalizeAppliesServerDefaults(t *testing.T) {
	var s Spec
	s.dir = t.TempDir()
	s.Normalize()

	if s.Listen != "127.0.0.1:8080" || s.DBDriver != "sqlite" || s.DBDSN != "underflow.db" {
		t.Errorf("normalize produced %+v", s)
	}
	if s.Pepper != PepperFile || s.Argon2Profile != "interactive" || s.SessionTTL != "12h" {
		t.Errorf("normalize produced %+v", s)
	}
	if s.Registration != "open" {
		t.Errorf("registration = %q, want the server default open", s.Registration)
	}
}

func TestResolveExpandsTildeAndRelativePaths(t *testing.T) {
	s := DefaultSpec(t.TempDir())
	got := s.Resolve("data/underflow.db")
	if got != filepath.Join(s.dir, "data", "underflow.db") {
		t.Errorf("Resolve = %q", got)
	}
	home, err := os.UserHomeDir()
	if err == nil {
		if want := filepath.Join(home, "uf.db"); s.Resolve("~/uf.db") != want {
			t.Errorf("Resolve(~) = %q, want %q", s.Resolve("~/uf.db"), want)
		}
	}
	if s.Resolve("") != "" {
		t.Error("Resolve of an empty path should stay empty")
	}
}

func hasIssue(issues []Issue, field string) bool {
	for _, i := range issues {
		if i.Field == field {
			return true
		}
	}
	return false
}
