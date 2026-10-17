// Package launcher provides a local web UI that configures, validates and
// supervises an `underflow serve` process. It is a development and
// single-machine operations convenience: it runs on loopback only, keeps no
// secrets in memory beyond the running configuration, and speaks the exact
// UF_* environment contract that `underflow serve` reads.
package launcher

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Pepper sources.
const (
	PepperFile      = "file"      // use the pepper file on disk (created if missing)
	PepperGenerated = "generated" // generate a new pepper (fails if one already exists)
)

// Validation severities.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Issue is a single validation problem with a stable field identifier so the
// UI can annotate the offending control.
type Issue struct {
	Field    string `json:"field"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

const minPepperBytes = 32

// httpClient is used only for loopback health probes.
var httpClient = http.Client{Timeout: 2 * time.Second}

// Spec is the full set of parameters accepted by `underflow serve`. Zero
// values mean "use the server default".
type Spec struct {
	Listen string `json:"listen"`
	Local  bool   `json:"local"`

	DBDriver string `json:"dbDriver"`
	DBDSN    string `json:"dbDsn"`

	Pepper         string `json:"pepper"`    // file | generated
	Overwrite      bool   `json:"overwrite"` // regenerate even if a pepper file exists
	PepperFilePath string `json:"pepperFilePath"`

	Registration string `json:"registration"`
	InviteCode   string `json:"inviteCode"`

	Argon2Profile string `json:"argon2Profile"`

	SessionTTL     string `json:"sessionTtl"`
	LogLevel       string `json:"logLevel"`
	TrustedProxies string `json:"trustedProxies"`
	TLSCert        string `json:"tlsCert"`
	TLSKey         string `json:"tlsKey"`
	Insecure       bool   `json:"insecure"`

	// Binary overrides the executable used to spawn `underflow serve`.
	// Empty means "this executable".
	Binary string `json:"binary"`

	// working directory of the launcher, used to resolve relative paths.
	dir string
}

// DefaultSpec returns the same configuration a bare `underflow serve --local`
// would use, with the pepper handled explicitly by the launcher.
func DefaultSpec(dir string) Spec {
	return Spec{
		Listen:        "127.0.0.1:8080",
		Local:         true,
		DBDriver:      "sqlite",
		DBDSN:         "underflow.db",
		Pepper:        PepperFile,
		Registration:  "closed",
		Argon2Profile: "interactive",
		SessionTTL:    "12h",
		LogLevel:      "info",
		dir:           dir,
	}
}

// Normalize trims free-text input and applies server defaults so the UI and
// the derived command agree on what will actually run.
func (s *Spec) Normalize() {
	s.Listen = strings.TrimSpace(s.Listen)
	s.DBDriver = strings.ToLower(strings.TrimSpace(s.DBDriver))
	s.DBDSN = strings.TrimSpace(s.DBDSN)
	s.Pepper = strings.ToLower(strings.TrimSpace(s.Pepper))
	s.PepperFilePath = strings.TrimSpace(s.PepperFilePath)
	s.Registration = strings.ToLower(strings.TrimSpace(s.Registration))
	s.InviteCode = strings.TrimSpace(s.InviteCode)
	s.Argon2Profile = strings.ToLower(strings.TrimSpace(s.Argon2Profile))
	s.SessionTTL = strings.TrimSpace(s.SessionTTL)
	s.LogLevel = strings.ToLower(strings.TrimSpace(s.LogLevel))
	s.TrustedProxies = strings.TrimSpace(s.TrustedProxies)
	s.TLSCert = strings.TrimSpace(s.TLSCert)
	s.TLSKey = strings.TrimSpace(s.TLSKey)
	s.Binary = strings.TrimSpace(s.Binary)

	if s.Listen == "" {
		s.Listen = "127.0.0.1:8080"
	}
	if s.DBDriver == "" {
		s.DBDriver = "sqlite"
	}
	if s.DBDSN == "" && s.DBDriver == "sqlite" {
		s.DBDSN = "underflow.db"
	}
	if s.Pepper == "" {
		s.Pepper = PepperFile
	}
	if s.Registration == "" {
		s.Registration = "open"
	}
	if s.Argon2Profile == "" {
		s.Argon2Profile = "interactive"
	}
	if s.SessionTTL == "" {
		s.SessionTTL = "12h"
	}
	if s.LogLevel == "" {
		s.LogLevel = "info"
	}
}

// Validate reports every configuration problem it can find, without stopping
// at the first one, so the UI can show a complete list.
func (s Spec) Validate() []Issue {
	var issues []Issue
	add := func(field, severity, format string, args ...any) {
		issues = append(issues, Issue{Field: field, Severity: severity, Message: fmt.Sprintf(format, args...)})
	}

	switch s.DBDriver {
	case "sqlite", "postgres":
	default:
		add("dbDsn", SeverityError, "unsupported database driver %q (use sqlite or postgres)", s.DBDriver)
	}
	if s.DBDSN == "" {
		add("dbDsn", SeverityError, "a database DSN or file path is required")
	} else if s.DBDriver == "sqlite" {
		if st, err := os.Stat(s.Resolve(s.DBDSN)); err == nil && st.IsDir() {
			add("dbDsn", SeverityError, "%s is a directory; sqlite needs a file path", s.Resolve(s.DBDSN))
		}
	}

	switch s.Pepper {
	case PepperFile, PepperGenerated:
	default:
		add("pepper", SeverityError, "unsupported pepper source %q", s.Pepper)
	}
	// The server requires a pepper except in insecure mode. Surface the gap
	// before the process starts so the failure is not a silent exit.
	pepperPath := s.PepperPath()
	if (s.Insecure || s.Pepper == PepperGenerated) && s.PepperFilePath == "" && pepperPath == "" {
		add("pepperFilePath", SeverityWarning,
			"no explicit pepper file: an unstructured database DSN has no matching .pepper path, so the server would fail to start")
	}
	if dir := filepath.Dir(pepperPath); pepperPath != "" && dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			add("pepperFilePath", SeverityError, "cannot create pepper directory %s: %v", dir, err)
		}
	}
	if s.Pepper == PepperGenerated && pepperPath == "" {
		add("pepperFilePath", SeverityError, "regenerating a pepper requires an explicit pepper file path")
	}
	if s.Insecure && s.DBDriver != "sqlite" {
		add("insecure", SeverityWarning, "insecure mode generates a random pepper on every restart: existing accounts will not be able to log in")
	}

	switch s.Argon2Profile {
	case "interactive", "moderate", "paranoid":
	default:
		add("argon2Profile", SeverityError, "unsupported argon2 profile %q (use interactive, moderate or paranoid)", s.Argon2Profile)
	}

	switch s.Registration {
	case "open", "closed", "invite":
	default:
		add("registration", SeverityError, "unsupported registration mode %q (use open, closed or invite)", s.Registration)
	}
	if s.Registration == "invite" && s.InviteCode == "" {
		add("inviteCode", SeverityError, "invite mode requires an invite code")
	}

	// The server maps only "debug" to a verbose level; everything else logs at
	// info, so the launcher offers just the two meaningful values.
	switch s.LogLevel {
	case "debug", "info":
	default:
		add("logLevel", SeverityError, "unsupported log level %q (use debug or info)", s.LogLevel)
	}

	if d, err := time.ParseDuration(s.SessionTTL); err != nil || d <= 0 {
		add("sessionTtl", SeverityError, "session TTL must be a positive duration such as 12h or 30m")
	}

	if (s.TLSCert == "") != (s.TLSKey == "") {
		if s.TLSCert == "" {
			add("tlsCert", SeverityError, "a TLS certificate is required when a key is set")
		} else {
			add("tlsKey", SeverityError, "a TLS key is required when a certificate is set")
		}
	}
	for _, f := range []struct{ field, path string }{
		{"tlsCert", s.TLSCert},
		{"tlsKey", s.TLSKey},
	} {
		if f.path == "" {
			continue
		}
		if _, err := os.Stat(s.Resolve(f.path)); err != nil {
			add(f.field, SeverityError, "file not found: %s", s.Resolve(f.path))
		}
	}

	if _, _, err := net.SplitHostPort(s.Listen); err != nil {
		add("listen", SeverityError, "listen address must be host:port, for example 127.0.0.1:8080")
	} else if err := s.CheckReachable(); err != nil {
		add("listen", SeverityError, "%v", err)
	}

	if s.Local && !isLoopbackListen(s.Listen) {
		add("local", SeverityWarning, "local mode redirects the listener to 127.0.0.1:8080 unless an explicit listen address is set")
	}

	return issues
}

// HasErrors reports whether issues contains a blocking problem.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == SeverityError {
			return true
		}
	}
	return false
}

// EffectiveListen returns the address the server will really bind, applying
// the same `--local` override that runServe applies.
func (s Spec) EffectiveListen() string {
	if s.Local && s.listenIsDefault() {
		return "127.0.0.1:8080"
	}
	return s.Listen
}

// listenIsDefault mirrors the CLI's "was --listen passed?" check. The UI
// cannot distinguish, so an explicit 127.0.0.1:8080 is treated as default.
func (s Spec) listenIsDefault() bool {
	return s.Listen == "" || s.Listen == "127.0.0.1:8080"
}

// CheckReachable performs a best-effort port availability and parse check.
func (s Spec) CheckReachable() error {
	host, port, err := net.SplitHostPort(s.EffectiveListen())
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("port %q is not a valid port number", port)
	}
	if n == 0 {
		return nil
	}
	if host != "" {
		if ip := net.ParseIP(host); ip == nil {
			if _, err := net.LookupHost(host); err != nil {
				return fmt.Errorf("cannot resolve host %q", host)
			}
		}
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("port %s is already in use (is the server already running?)", port)
	}
	_ = ln.Close()
	return nil
}

// Resolve turns a possibly relative, possibly ~-prefixed path into an absolute
// path using the launcher's working directory.
func (s Spec) Resolve(p string) string {
	if p == "" {
		return ""
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p[1:], "/"), `\`))
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.dir, p)
	}
	return filepath.Clean(p)
}

// PepperPath is the file the server pepper is read from and written to.
func (s Spec) PepperPath() string {
	if s.PepperFilePath != "" {
		return s.Resolve(s.PepperFilePath)
	}
	if s.DBDriver == "sqlite" && s.DBDSN != "" {
		// Match the server's own convention: a pepper file next to the database.
		return s.Resolve(s.DBDSN) + ".pepper"
	}
	return ""
}

// dsn returns the value for UF_DB_DSN. SQLite takes a file path, so relative
// paths are resolved against the launcher's working directory; PostgreSQL
// takes a connection string that must be passed through untouched.
func (s Spec) dsn() string {
	if s.DBDriver == "sqlite" {
		return s.Resolve(s.DBDSN)
	}
	return s.DBDSN
}

// Env returns the UF_* environment overrides for this spec.
func (s Spec) Env() map[string]string {
	env := map[string]string{
		"UF_LISTEN_ADDR":    s.EffectiveListen(),
		"UF_DB_DRIVER":      s.DBDriver,
		"UF_DB_DSN":         s.dsn(),
		"UF_ARGON2_PROFILE": s.Argon2Profile,
		"UF_SESSION_TTL":    s.SessionTTL,
		"UF_LOG_LEVEL":      s.LogLevel,
		"UF_REGISTRATION":   s.Registration,
	}
	if s.InviteCode != "" {
		env["UF_INVITE_CODE"] = s.InviteCode
	}
	if s.TrustedProxies != "" {
		env["UF_TRUSTED_PROXIES"] = s.TrustedProxies
	}
	if s.TLSCert != "" {
		env["UF_TLS_CERT"] = s.Resolve(s.TLSCert)
	}
	if s.TLSKey != "" {
		env["UF_TLS_KEY"] = s.Resolve(s.TLSKey)
	}
	if s.Insecure {
		env["UF_INSECURE"] = "1"
	}
	if p := s.PepperPath(); p != "" {
		env["UF_SERVER_PEPPER_FILE"] = p
	}
	return env
}

// Args returns the command-line arguments appended to the binary.
func (s Spec) Args() []string {
	args := []string{"serve"}
	if s.Local {
		args = append(args, "--local")
	}
	return args
}

// Result is everything the launcher derived from a spec: what it will run, how
// to reach it, and which problems remain.
type Result struct {
	Env          map[string]string `json:"env"`
	Args         []string          `json:"args"`
	URL          string            `json:"url"`
	ProbeURL     string            `json:"probeUrl"`
	Command      string            `json:"command"`
	PepperPath   string            `json:"pepperPath"`
	PepperExists bool              `json:"pepperExists"`
	Ready        bool              `json:"ready"`
	Issues       []Issue           `json:"issues"`
}

// Derive renders the resolved runtime configuration for a spec and validates
// it. It never touches the network for anything other than the port check.
func (s Spec) Derive(binary string) Result {
	s.Normalize()
	issues := s.Validate()
	env := s.Env()
	res := Result{
		Env:      env,
		Args:     s.Args(),
		URL:      s.URL(),
		ProbeURL: s.ProbeURL(),
		Command:  commandLine(binary, s.Args(), env),
		Issues:   issues,
		Ready:    !HasErrors(issues),
	}
	if p := s.PepperPath(); p != "" {
		res.PepperPath = p
		if _, err := os.Stat(p); err == nil {
			res.PepperExists = true
		}
	}
	return res
}

// scheme returns http or https depending on the TLS configuration.
func (s Spec) scheme() string {
	if s.TLSCert != "" && s.TLSKey != "" {
		return "https"
	}
	return "http"
}

// URL is the browser-facing address of the configured server.
func (s Spec) URL() string {
	return s.scheme() + "://" + browserHost(s.EffectiveListen())
}

// ProbeURL is the health endpoint used to decide whether the server is up.
// Port 0 (an OS-assigned port) cannot be probed.
func (s Spec) ProbeURL() string {
	host, port, err := net.SplitHostPort(s.EffectiveListen())
	if err != nil || port == "0" {
		return ""
	}
	return s.scheme() + "://" + net.JoinHostPort(probeHost(host), port) + "/api/v1/healthz"
}

// browserHost rewrites wildcard binds into something a browser can open.
func browserHost(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(probeHost(host), port)
}

func probeHost(host string) string {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "127.0.0.1"
	}
	return host
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// commandLine renders a copy-pasteable command for the resolved settings.
func commandLine(binary string, args []string, env map[string]string) string {
	keys := []string{
		"UF_LISTEN_ADDR", "UF_DB_DRIVER", "UF_DB_DSN", "UF_REGISTRATION",
		"UF_INVITE_CODE", "UF_ARGON2_PROFILE", "UF_SESSION_TTL", "UF_LOG_LEVEL",
		"UF_TLS_CERT", "UF_TLS_KEY", "UF_TRUSTED_PROXIES", "UF_INSECURE",
		"UF_SERVER_PEPPER_FILE",
	}
	var b strings.Builder
	for _, k := range keys {
		v, ok := env[k]
		if !ok {
			continue
		}
		if k == "UF_INVITE_CODE" {
			v = "REDACTED"
		}
		fmt.Fprintf(&b, "%s=%s ", k, quoteIfNeeded(v))
	}
	fmt.Fprintf(&b, "%s %s", quoteIfNeeded(binary), strings.Join(args, " "))
	return b.String()
}

func quoteIfNeeded(v string) string {
	if v == "" || strings.ContainsAny(v, " \t\"'$&|;<>()") {
		return strconv.Quote(v)
	}
	return v
}

// PepperStatus describes the on-disk pepper without revealing it.
type PepperStatus struct {
	Path        string `json:"path"`
	Exists      bool   `json:"exists"`
	Size        int64  `json:"size"`
	Fingerprint string `json:"fingerprint"` // short display hash, not the secret
	ReadError   string `json:"readError"`
}

// GeneratePepper creates a new 32-byte pepper at path, refusing to clobber an
// existing file unless overwrite is set.
func GeneratePepper(path string, overwrite bool) (PepperStatus, error) {
	if path == "" {
		return PepperStatus{}, errors.New("no pepper file path available")
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return PepperStatus{}, fmt.Errorf("%s already exists (enable overwrite to replace it)", path)
		}
	}
	raw := make([]byte, minPepperBytes)
	if _, err := rand.Read(raw); err != nil {
		return PepperStatus{}, err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return PepperStatus{}, fmt.Errorf("create pepper directory: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(raw)), 0o600); err != nil {
		return PepperStatus{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return PepperStatus{}, err
	}
	return InspectPepper(path), nil
}

// InspectPepper reads pepper metadata (never the value itself).
func InspectPepper(path string) PepperStatus {
	st := PepperStatus{Path: path}
	if path == "" {
		st.ReadError = "no pepper file path configured"
		return st
	}
	info, err := os.Stat(path)
	if err != nil {
		return st
	}
	st.Exists = true
	st.Size = info.Size()
	data, err := os.ReadFile(path) // #nosec G304 -- operator-selected path.
	if err != nil {
		st.ReadError = err.Error()
		return st
	}
	sum := fingerprint(strings.TrimSpace(string(data)))
	st.Fingerprint = sum
	return st
}

// fingerprint returns a short, non-reversible identifier for the pepper so an
// operator can tell two peppers apart without exposing either.
func fingerprint(secret string) string {
	// FNV-1a is fine here: this is a display aid, not a security control.
	var h uint32 = 2166136261
	for i := 0; i < len(secret); i++ {
		h ^= uint32(secret[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}

// ProbeReady polls a health endpoint until it answers 200 or the timeout
// expires. It returns nil once the server is up.
func ProbeReady(probeURL string, timeout time.Duration) error {
	if probeURL == "" {
		return errors.New("no probe URL")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(probeURL) // #nosec G107 -- loopback health probe of the operator's own server.
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("no healthy response from %s within %s", probeURL, timeout)
}

// OpenBrowser launches the platform's default browser.
func OpenBrowser(target string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	case "darwin":
		return exec.Command("open", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}
