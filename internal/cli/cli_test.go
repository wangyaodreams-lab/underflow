package cli_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangyaodreams-lab/underflow/internal/cli"
	"github.com/wangyaodreams-lab/underflow/internal/config"
	"github.com/wangyaodreams-lab/underflow/internal/server"
	"github.com/wangyaodreams-lab/underflow/internal/store/sqlite"
)

func newBackend(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := sqlite.Open(context.Background(), sqlite.Options{Path: filepath.Join(dir, "underflow.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Config{
		DBDriver:        "sqlite",
		ServerPepper:    bytes.Repeat([]byte{0x7a}, 32),
		Registration:    config.RegistrationOpen,
		Argon2Profile:   "interactive",
		SessionTTL:      time.Hour,
		MaxRequestBytes: 8 << 20,
	}
	srv := server.New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, dir
}

// runCLI executes the CLI with stdin wired to a pipe.
func runCLI(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })
	go func() {
		_, _ = io.WriteString(w, stdin)
		_ = w.Close()
	}()

	var buf bytes.Buffer
	root := cli.NewRootCmd()
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err = root.Execute()
	return buf.String(), err
}

func TestCLIRemoteRoundTrip(t *testing.T) {
	ts, dir := newBackend(t)
	cfgDir := filepath.Join(dir, "conf")
	base := []string{"--config-dir", cfgDir}
	withBase := func(args ...string) []string { return append(args, base...) }

	// register
	out, err := runCLI(t, "Password123!\nPassword123!\n",
		withBase("register", "--server", ts.URL, "--email", "alice@example.com")...)
	if err != nil {
		t.Fatalf("register: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Registered alice@example.com") {
		t.Fatalf("unexpected register output: %s", out)
	}

	// add an item with a generated password
	out, err = runCLI(t, "", withBase("item", "add", "--name", "example.com", "--username", "alice",
		"--url", "https://example.com", "--generate")...)
	if err != nil {
		t.Fatalf("item add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "example.com") {
		t.Fatalf("unexpected add output: %s", out)
	}

	// list
	out, err = runCLI(t, "", withBase("item", "list", "--show-passwords")...)
	if err != nil {
		t.Fatalf("item list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "example.com") || !strings.Contains(out, "alice") {
		t.Fatalf("unexpected list output: %s", out)
	}

	// get
	out, err = runCLI(t, "", withBase("item", "get", "example.com", "--show")...)
	if err != nil {
		t.Fatalf("item get: %v\n%s", err, out)
	}
	if !strings.Contains(out, "password:") {
		t.Fatalf("get did not reveal password: %s", out)
	}

	// lock then a locked command must fail
	if out, err = runCLI(t, "", withBase("lock")...); err != nil {
		t.Fatalf("lock: %v\n%s", err, out)
	}
	if _, err = runCLI(t, "", withBase("item", "list")...); err == nil {
		t.Fatal("item list succeeded while locked")
	}

	// unlock with the master password and read again
	out, err = runCLI(t, "Password123!\n", withBase("unlock")...)
	if err != nil {
		t.Fatalf("unlock: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Unlocked") {
		t.Fatalf("unexpected unlock output: %s", out)
	}

	// export as JSON
	out, err = runCLI(t, "", withBase("export", "--format", "json")...)
	if err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	if !strings.Contains(out, "example.com") {
		t.Fatalf("export missing item: %s", out)
	}
}

func TestCLILoginWrongPassword(t *testing.T) {
	ts, dir := newBackend(t)
	cfgDir := filepath.Join(dir, "conf")
	cfg := []string{"--config-dir", cfgDir}

	if _, err := runCLI(t, "Password123!\nPassword123!\n",
		append([]string{"register", "--server", ts.URL, "--email", "bob@example.com"}, cfg...)...); err != nil {
		t.Fatalf("register: %v", err)
	}
	// logout then attempt login with a wrong password
	if _, err := runCLI(t, "", append([]string{"logout"}, cfg...)...); err != nil {
		t.Fatalf("logout: %v", err)
	}
	_, err := runCLI(t, "WrongPassword123!\n",
		append([]string{"login", "--server", ts.URL, "--email", "bob@example.com"}, cfg...)...)
	if err == nil {
		t.Fatal("login with wrong password succeeded")
	}
}
