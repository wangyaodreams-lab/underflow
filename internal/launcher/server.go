package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const stateFileName = "launcher.json"

// state is the persisted launcher configuration.
type state struct {
	Version int  `json:"version"`
	Spec    Spec `json:"spec"`
}

func statePath(dir string) string { return filepath.Join(dir, stateFileName) }

// loadState reads the saved configuration, falling back to defaults when the
// file does not exist yet. workDir is where the supervised server runs, so
// relative paths in a fresh configuration resolve there.
func loadState(workDir, dir string) (Spec, error) {
	def := DefaultSpec(workDir)
	data, err := os.ReadFile(statePath(dir)) // #nosec G304 -- launcher-owned config path.
	if errors.Is(err, os.ErrNotExist) {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return def, fmt.Errorf("read %s: %w", statePath(dir), err)
	}
	spec := st.Spec
	spec.dir = workDir
	spec.Normalize()
	return spec, nil
}

// saveState writes the configuration atomically with owner-only permissions.
func saveState(dir string, spec Spec) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	saved := spec
	saved.dir = ""
	data, err := json.MarshalIndent(state{Version: 1, Spec: saved}, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, statePath(dir)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Server hosts the launcher UI and its control API.
type Server struct {
	dir      string // working directory the supervised server runs in
	stateDir string // directory holding launcher.json
	manager  *Manager
	binary   string

	// argv builds the command line for a spec. It is a field so tests can
	// substitute a scripted stand-in for the real server binary.
	argv func(spec Spec, binary string) []string

	// keepalive is the SSE comment interval; shortened in tests.
	keepalive time.Duration

	mu   sync.Mutex
	spec Spec
	host string // launcher's own listen address, for origin checks
}

// Options configures the launcher server.
type Options struct {
	WorkDir  string // directory the server is run from (resolves relative paths)
	StateDir string // directory holding launcher.json
	Binary   string // executable to spawn
	Addr     string // launcher listen address
}

// NewServer prepares the launcher from persisted state.
func NewServer(opt Options) (*Server, error) {
	if opt.WorkDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		opt.WorkDir = wd
	}
	if opt.StateDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		opt.StateDir = filepath.Join(base, "underflow")
	}
	if opt.Binary == "" {
		self, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("cannot determine own executable: %w", err)
		}
		opt.Binary = self
	}
	spec, err := loadState(opt.WorkDir, opt.StateDir)
	if err != nil {
		return nil, err
	}
	return &Server{
		dir:       opt.WorkDir,
		stateDir:  opt.StateDir,
		manager:   NewManager(),
		binary:    opt.Binary,
		argv:      defaultArgv,
		keepalive: 15 * time.Second,
		spec:      spec,
		host:      opt.Addr,
	}, nil
}

// defaultArgv is the real command line: the binary followed by `serve` flags.
func defaultArgv(spec Spec, binary string) []string {
	return append([]string{binary}, spec.Args()...)
}

// Spec returns the current configuration.
func (s *Server) Spec() Spec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spec
}

// SetSpec replaces the configuration. A running server is stopped because its
// environment is fixed at spawn time.
func (s *Server) SetSpec(spec Spec) (Spec, error) {
	spec.dir = s.dir
	spec.Normalize()
	if err := saveState(s.stateDir, spec); err != nil {
		return spec, err
	}
	switch st := s.manager.State(); st.Status {
	case StatusRunning, StatusStarting:
		if err := s.manager.Stop(); err != nil {
			return spec, err
		}
	}
	s.mu.Lock()
	s.spec = spec
	s.mu.Unlock()
	return spec, nil
}

// Bootstrap is the initial payload the UI renders from.
type Bootstrap struct {
	Spec    Spec           `json:"spec"`
	Result  Result         `json:"result"`
	State   State          `json:"state"`
	Pepper  PepperStatus   `json:"pepper"`
	WorkDir string         `json:"workDir"`
	StateD  string         `json:"stateDir"`
	Binary  string         `json:"binary"`
	Choices map[string]any `json:"choices"`
}

// Handler returns the routed HTTP handler for the launcher.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/bootstrap", s.guard(s.handleBootstrap))
	mux.HandleFunc("/api/spec", s.guard(s.handleSpec))
	mux.HandleFunc("/api/start", s.guard(s.handleStart))
	mux.HandleFunc("/api/stop", s.guard(s.handleStop))
	mux.HandleFunc("/api/restart", s.guard(s.handleRestart))
	mux.HandleFunc("/api/pepper", s.guard(s.handlePepper))
	mux.HandleFunc("/api/state", s.guard(s.handleState))
	mux.HandleFunc("/api/logs", s.guard(s.handleLogs))
	return mux
}

// Serve listens on addr and serves the launcher until the process exits.
func (s *Server) Serve(addr string) error {
	s.mu.Lock()
	s.host = addr
	s.mu.Unlock()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.Serve(ln)
}

// Manager exposes the process manager (used by tests and the CLI).
func (s *Server) Manager() *Manager { return s.manager }

// Binary returns the executable used to spawn the server.
func (s *Server) Binary() string { return s.binary }

// --- handlers ---

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	page, err := readAsset("index.html")
	if err != nil {
		http.Error(w, "launcher UI is missing from this build", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	spec := s.Spec()
	writeJSON(w, http.StatusOK, Bootstrap{
		Spec:    spec,
		Result:  spec.Derive(s.binary),
		State:   s.manager.State(),
		Pepper:  InspectPepper(spec.PepperPath()),
		WorkDir: s.dir,
		StateD:  s.stateDir,
		Binary:  s.binary,
		Choices: map[string]any{
			"profiles":      []string{"interactive", "moderate", "paranoid"},
			"registrations": []string{"open", "closed", "invite"},
			"drivers":       []string{"sqlite", "postgres"},
			"logLevels":     []string{"debug", "info"},
			"pepperSources": []string{PepperFile, PepperGenerated},
		},
	})
}

// specRequest is the payload accepted by /api/spec.
type specRequest struct {
	Spec Spec `json:"spec"`
}

func (s *Server) handleSpec(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req specRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Spec.dir = s.dir
	req.Spec.Normalize()
	res := req.Spec.Derive(s.binary)
	saved := false
	if !HasErrors(res.Issues) {
		stored, err := s.SetSpec(req.Spec)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "save_failed", err.Error())
			return
		}
		req.Spec = stored
		res = req.Spec.Derive(s.binary)
		saved = true
	}
	writeJSON(w, http.StatusOK, specResponse(req.Spec, res, saved))
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req specRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Spec.dir = s.dir
	req.Spec.Normalize()
	if err := saveState(s.stateDir, req.Spec); err != nil {
		writeErr(w, http.StatusInternalServerError, "save_failed", err.Error())
		return
	}
	s.mu.Lock()
	s.spec = req.Spec
	s.mu.Unlock()

	if _, err := s.manager.StartArgv(req.Spec, s.argv(req.Spec, s.binary), s.dir); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"state": s.manager.State(), "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.manager.State()})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if err := s.manager.Stop(); err != nil {
		writeErr(w, http.StatusInternalServerError, "stop_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.manager.State()})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req specRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Spec.dir = s.dir
	req.Spec.Normalize()
	if err := s.manager.Stop(); err != nil {
		writeErr(w, http.StatusInternalServerError, "restart_failed", err.Error())
		return
	}
	if _, err := s.manager.StartArgv(req.Spec, s.argv(req.Spec, s.binary), s.dir); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"state": s.manager.State(), "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.manager.State()})
}

func (s *Server) handlePepper(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Overwrite bool `json:"overwrite"`
		Spec      Spec `json:"spec"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Spec.dir = s.dir
	req.Spec.Normalize()
	st, err := GeneratePepper(req.Spec.PepperPath(), req.Overwrite)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "pepper_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pepper": st})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	spec := s.Spec()
	writeJSON(w, http.StatusOK, map[string]any{
		"state":  s.manager.State(),
		"result": spec.Derive(s.binary),
		"pepper": InspectPepper(spec.PepperPath()),
	})
}

// handleLogs streams server output as Server-Sent Events. A client that
// reconnects with Last-Event-ID receives exactly the lines it missed.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "no_streaming", "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	after := uint64(0)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		after = parseUint(v)
	} else if v := r.URL.Query().Get("after"); v != "" {
		after = parseUint(v)
	}

	logs := s.manager.Logs()
	// Subscribe before replaying so nothing can slip between the two.
	head, ch := logs.subscribe()
	defer logs.detach(ch)

	for _, line := range logs.since(after) {
		if !writeSSE(w, line) {
			return
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(s.keepalive)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case line, open := <-ch:
			if !open {
				return
			}
			// Lines already covered by the replay above arrive only if they
			// were published between subscribe and replay.
			if line.Seq <= head {
				continue
			}
			if !writeSSE(w, line) {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, line logLine) bool {
	// SSE data fields cannot contain raw newlines.
	text := strings.ReplaceAll(line.Text, "\r", "")
	text = strings.ReplaceAll(text, "\n", "\\n")
	_, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", line.Seq, text)
	return err == nil
}

// specResponse is the common body returned by spec and start endpoints.
func specResponse(spec Spec, res Result, saved bool) map[string]any {
	return map[string]any{
		"spec":   spec,
		"result": res,
		"saved":  saved,
		"pepper": InspectPepper(spec.PepperPath()),
	}
}

// --- middleware ---

// guard rejects requests that do not target the loopback launcher. This blocks
// DNS-rebinding attacks, which would otherwise let a remote page drive the
// control API through the user's browser.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedOrigin(r) {
			writeErr(w, http.StatusForbidden, "forbidden_origin",
				"the launcher only accepts requests from its own page")
			return
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func (s *Server) allowedOrigin(r *http.Request) bool {
	s.mu.Lock()
	self := s.host
	s.mu.Unlock()
	if !loopbackHost(r.Host, self) {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return loopbackHost(u.Host, self)
}

// loopbackHost accepts a host:port whose host is loopback and whose port is
// the launcher's own port. An empty self port disables the port check.
func loopbackHost(hostport, self string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if _, selfPort, err := net.SplitHostPort(self); err == nil && selfPort != "" && port != selfPort {
		return false
	}
	switch {
	case host == "":
		return false
	case strings.EqualFold(host, "localhost"):
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return false
	}
	return true
}

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return false
	}
	return true
}

// --- small helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return false
	}
	return true
}

func parseUint(s string) uint64 {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}
