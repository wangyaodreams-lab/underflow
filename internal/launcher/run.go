package launcher

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Process statuses reported to the UI.
const (
	StatusStopped  = "stopped"
	StatusStarting = "starting"
	StatusRunning  = "running"
	StatusStopping = "stopping"
	StatusExited   = "exited"
	StatusFailed   = "failed"
)

// State is a snapshot of the supervised server process.
type State struct {
	Status    string    `json:"status"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"startedAt"`
	ExitedAt  time.Time `json:"exitedAt"`
	ExitCode  int       `json:"exitCode"`
	Error     string    `json:"error"`
	URL       string    `json:"url"`
	ProbeURL  string    `json:"probeUrl"`
	Config    string    `json:"config"`
	Args      []string  `json:"args"`
	Pepper    string    `json:"pepperPath"`
	LogLines  int       `json:"logLines"`
	Started   bool      `json:"started"` // true once the port answered
}

// Manager owns at most one supervised server process at a time.
type Manager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   *os.File // write end of the child's stdin, closed to unblock it
	state   State
	logs    *logRing
	stopped bool // set when a stop was requested, to distinguish from a crash
	run     uint64
}

// NewManager returns a manager with an empty log buffer.
func NewManager() *Manager {
	return &Manager{state: State{Status: StatusStopped}, logs: newLogRing(2000)}
}

// Logs exposes the shared log buffer.
func (m *Manager) Logs() *logRing { return m.logs }

// State returns a copy of the current process state.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.state
	if st.LogLines == 0 {
		st.LogLines = len(m.logs.since(0))
	}
	return st
}

// Start spawns `underflow serve` for the given spec. Any previous process is
// stopped first. The returned state reflects the process launch, not
// readiness; readiness is reported through the state as the probe succeeds.
func (m *Manager) Start(spec Spec, binary, cwd string) (State, error) {
	return m.StartArgv(spec, append([]string{binary}, spec.Args()...), cwd)
}

// StartArgv spawns an explicit command line for a spec. The launcher builds
// the real `underflow serve` invocation; tests substitute a scripted stand-in.
func (m *Manager) StartArgv(spec Spec, argv []string, cwd string) (State, error) {
	spec.dir = cwd
	spec.Normalize()
	if len(argv) == 0 {
		return m.State(), errors.New("no command to run")
	}

	if issues := spec.Validate(); HasErrors(issues) {
		return m.State(), errors.New(firstError(issues))
	}
	if err := m.Stop(); err != nil {
		return m.State(), err
	}

	// Materialise the pepper before the server starts: it must exist so the
	// server never has a reason to fall back to a weaker path.
	if spec.Pepper == PepperGenerated && !spec.Insecure {
		if _, err := GeneratePepper(spec.PepperPath(), spec.Overwrite); err != nil {
			return m.State(), fmt.Errorf("pepper: %w", err)
		}
	}

	res := spec.Derive(argv[0])
	// The server prompts for an admin password only in a configuration the
	// launcher rejects, so an empty stdin makes such a prompt fail fast. The
	// write end is kept so Stop can close it to unblock a waiting child.
	r, w, err := os.Pipe()
	if err != nil {
		return m.State(), fmt.Errorf("create stdin pipe: %w", err)
	}
	defer r.Close()

	state, err := m.startArgv(spec, argv, cwd, res.Env, res.Command, w)
	if err != nil {
		_ = w.Close()
		return state, err
	}
	return state, nil
}

// startArgv launches exactly the given argv. Start builds it from a spec;
// tests use it to run a scripted stand-in instead of a real server.
func (m *Manager) startArgv(spec Spec, argv []string, cwd string, env map[string]string, description string, stdin *os.File) (State, error) {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- operator-selected binary and validated arguments.
	cmd.Dir = cwd
	cmd.Env = mergeEnv(os.Environ(), env)
	switch {
	case stdin != nil:
		cmd.Stdin = stdin
	default:
		cmd.Stdin = bytes.NewReader(nil)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return m.State(), err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return m.State(), err
	}
	if err := cmd.Start(); err != nil {
		return m.State(), fmt.Errorf("start %s: %w", argv[0], err)
	}

	m.mu.Lock()
	m.cmd = cmd
	m.stdin = stdin
	m.stopped = false
	m.run++
	run := m.run
	m.state = State{
		Status:    StatusStarting,
		PID:       cmd.Process.Pid,
		StartedAt: time.Now(),
		URL:       spec.URL(),
		ProbeURL:  spec.ProbeURL(),
		Config:    description,
		Args:      argv[1:],
		Pepper:    spec.PepperPath(),
	}
	m.mu.Unlock()

	m.logs.clear()
	m.logs.add(fmt.Sprintf("$ %s", description))
	m.logs.add(fmt.Sprintf("launched pid %d", cmd.Process.Pid))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); m.pipe(stdout) }()
	go func() { defer wg.Done(); m.pipe(stderr) }()

	done := make(chan struct{})
	go m.probe(run, spec.ProbeURL(), done)

	go func() {
		wg.Wait()
		err := cmd.Wait()
		close(done)
		m.finish(run, err)
	}()

	return m.State(), nil
}

// Stop terminates the server process, giving it a chance to shut down
// gracefully. It is safe to call when nothing is running.
func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	if cmd == nil || cmd.Process == nil {
		m.mu.Unlock()
		return nil
	}
	m.stopped = true
	m.state.Status = StatusStopping
	stdin := m.stdin
	m.mu.Unlock()

	m.logs.add("stopping server…")
	if err := terminate(cmd.Process); err != nil && !errors.Is(err, os.ErrProcessDone) {
		// Fall back to a hard kill if the graceful signal failed.
		_ = cmd.Process.Kill()
	}
	if !m.waitForExit(10 * time.Second) {
		// Still alive: close stdin so a process waiting on input can end.
		if stdin != nil {
			_ = stdin.Close()
		}
		if !m.waitForExit(5 * time.Second) {
			_ = cmd.Process.Kill()
			m.waitForExit(3 * time.Second)
		}
	}
	return nil
}

func (m *Manager) waitForExit(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		done := m.cmd == nil
		m.mu.Unlock()
		if done {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// finish records the process exit. It ignores results from a superseded run
// so that a fast restart cannot be undone by the previous process's exit.
func (m *Manager) finish(run uint64, err error) {
	m.mu.Lock()
	if run != m.run {
		m.mu.Unlock()
		return
	}
	intentional := m.stopped
	m.cmd = nil
	if m.stdin != nil {
		_ = m.stdin.Close()
		m.stdin = nil
	}
	m.state.ExitedAt = time.Now()

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	m.state.ExitCode = code
	switch {
	case intentional:
		m.state.Status = StatusStopped
		m.state.Error = ""
	case code == 0:
		m.state.Status = StatusExited
		m.state.Error = "the server exited on its own"
	default:
		m.state.Status = StatusFailed
		m.state.Error = fmt.Sprintf("the server exited with code %d", code)
	}
	final := m.state.Error
	m.mu.Unlock()

	switch {
	case intentional:
		m.logs.add("server stopped")
	case final != "":
		m.logs.add("error: " + final)
	}
}

// probe watches the health endpoint and promotes the state to running. It
// stops as soon as the process exits, so a dead process is never promoted.
func (m *Manager) probe(run uint64, probeURL string, done <-chan struct{}) {
	if probeURL == "" {
		m.mu.Lock()
		if run == m.run && m.state.Status == StatusStarting {
			m.state.Status = StatusRunning
			m.state.Started = true
			m.state.Error = ""
		}
		m.mu.Unlock()
		return
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return
		default:
		}
		m.mu.Lock()
		stale := run != m.run
		status := m.state.Status
		m.mu.Unlock()
		if stale || status != StatusStarting {
			return // superseded, exited or already running
		}
		if err := ProbeReady(probeURL, 1*time.Second); err == nil {
			m.mu.Lock()
			alive := run == m.run && m.cmd != nil
			if alive && m.state.Status == StatusStarting {
				m.state.Status = StatusRunning
				m.state.Started = true
				m.state.Error = ""
			}
			m.mu.Unlock()
			if alive {
				m.logs.add("server is answering health checks at " + probeURL)
			}
			return
		}
	}
	m.mu.Lock()
	if run == m.run && m.state.Status == StatusStarting {
		m.state.Error = "the server did not answer health checks within 20s"
	}
	m.mu.Unlock()
}

// pipe copies child output into the log ring, one line at a time.
func (m *Manager) pipe(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		m.logs.add(sc.Text())
	}
	if err := sc.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		m.logs.add("log stream error: " + err.Error())
	}
}

// --- helpers ---

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// StripANSI removes terminal colour codes from captured output.
func StripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func firstError(issues []Issue) string {
	for _, i := range issues {
		if i.Severity == SeverityError {
			return i.Message
		}
	}
	return "invalid configuration"
}

func mergeEnv(base []string, overrides map[string]string) []string {
	seen := make(map[string]bool, len(overrides))
	out := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if v, replace := overrides[k]; replace {
			// Preserve the OS's case for Windows compatibility.
			seen[strings.ToUpper(k)] = true
			out = append(out, k+"="+v)
			continue
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if seen[strings.ToUpper(k)] {
			continue
		}
		out = append(out, k+"="+overrides[k])
	}
	return out
}

// terminate asks the process to shut down. Windows has no SIGTERM, so a kill
// is the only option there; the server's graceful path needs no special
// handling because it holds no unflushed state.
func terminate(p *os.Process) error {
	if runtime.GOOS == "windows" {
		return p.Kill()
	}
	return p.Signal(os.Interrupt)
}
