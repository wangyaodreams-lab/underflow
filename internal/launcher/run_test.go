package launcher

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProcessState produces a real *os.ProcessState with the given exit code,
// so *exec.ExitError behaves exactly as it does in production.
func fakeProcessState(t *testing.T, code int) *os.ProcessState {
	t.Helper()
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "exit", strconv.Itoa(code))
		err := cmd.Run()
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("expected an ExitError from exit %d, got %v", code, err)
		}
		return ee.ProcessState
	}
	cmd := exec.Command("sh", "-c", "exit "+strconv.Itoa(code))
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an ExitError from exit %d, got %v", code, err)
	}
	return ee.ProcessState
}

// fakeServerScript writes a stand-in for `underflow serve` that prints known
// lines and then exits. It cannot stay alive readably on Windows without
// leaving a grandchild process behind, so process-exit reporting is covered by
// TestFinishClassifiesExit instead of a long-running child.
func fakeServerScript(t *testing.T, dir string, exitCode int, lines ...string) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "fake-server.cmd")
		script := "@echo off\r\n"
		for _, l := range lines {
			script += "echo " + l + "\r\n"
		}
		if exitCode != 0 {
			script += "exit /b " + strconv.Itoa(exitCode) + "\r\n"
		}
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatalf("write fake server: %v", err)
		}
		return []string{"cmd", "/c", path}
	}
	path := filepath.Join(dir, "fake-server")
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	for _, l := range lines {
		b.WriteString("echo " + l + "\n")
	}
	if exitCode != 0 {
		b.WriteString("exit " + strconv.Itoa(exitCode) + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		t.Fatalf("write fake server: %v", err)
	}
	return []string{path}
}

// startFake starts a scripted stand-in for the server binary in place of argv.
func (m *Manager) startFake(spec Spec, argv []string, cwd string) (State, error) {
	return m.StartArgv(spec, argv, cwd)
}

func specForManager(t *testing.T) (Spec, string) {
	t.Helper()
	dir := t.TempDir()
	s := DefaultSpec(dir)
	// Port 0 means "no probe", which keeps the test off the network.
	s.Listen = "127.0.0.1:0"
	// No --local, so the fake script is invoked with plain `serve`.
	s.Local = false
	return s, dir
}

func TestManagerStartCapturesOutputAndSurfacesExit(t *testing.T) {
	spec, dir := specForManager(t)
	argv := fakeServerScript(t, dir, 0, "fake server ready", "second line")

	m := NewManager()
	if _, err := m.startFake(spec, argv, dir); err != nil {
		t.Fatalf("Start: %v", err)
	}

	waitFor(t, 10*time.Second, func() bool {
		switch m.State().Status {
		case StatusExited, StatusFailed:
			return true
		}
		return false
	})

	lines := m.Logs().since(0)
	joined := joinLines(lines)
	if !strings.Contains(joined, "fake server ready") {
		t.Errorf("captured output = %q, want the child's stdout", joined)
	}
	if !strings.Contains(joined, "launched pid") {
		t.Errorf("captured output = %q, want the launch banner", joined)
	}
	if st := m.State(); st.PID <= 0 {
		t.Errorf("pid = %d, want the child's pid", st.PID)
	}
	// A process that ends on its own is reported, not silently swallowed.
	if st := m.State(); st.Status != StatusExited || st.Error == "" {
		t.Errorf("state = %+v, want an explained clean exit", st)
	}
}

func TestManagerReportsNonZeroExit(t *testing.T) {
	spec, dir := specForManager(t)
	argv := fakeServerScript(t, dir, 3, "about to fail")

	m := NewManager()
	if _, err := m.startFake(spec, argv, dir); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		return m.State().Status == StatusFailed
	})
	if st := m.State(); st.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", st.ExitCode)
	}
	if st := m.State(); !strings.Contains(st.Error, "code 3") {
		t.Errorf("error = %q, want it to name the exit code", st.Error)
	}
}

// finish() decides how an exit is reported, so it is tested directly rather
// than through a long-running child process.
func TestFinishClassifiesExit(t *testing.T) {
	cases := []struct {
		name        string
		stopFirst   bool
		err         error
		wantStatus  string
		wantError   bool
		wantLogWord string
	}{
		{name: "deliberate stop", stopFirst: true, wantStatus: StatusStopped, wantError: false, wantLogWord: "server stopped"},
		{name: "clean self-exit", err: nil, wantStatus: StatusExited, wantError: true, wantLogWord: "exit"},
		{name: "crash", err: &exec.ExitError{ProcessState: fakeProcessState(t, 2)}, wantStatus: StatusFailed, wantError: true, wantLogWord: "code 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager()
			m.mu.Lock()
			m.state = State{Status: StatusStarting, PID: 4242}
			m.stopped = tc.stopFirst
			m.mu.Unlock()

			m.finish(0, tc.err)

			st := m.State()
			if st.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", st.Status, tc.wantStatus)
			}
			if gotErr := st.Error != ""; gotErr != tc.wantError {
				t.Errorf("error = %q, want present=%v", st.Error, tc.wantError)
			}
			if st.ExitedAt.IsZero() {
				t.Error("ExitedAt should be recorded")
			}
			if joined := joinLines(m.Logs().since(0)); !strings.Contains(joined, tc.wantLogWord) {
				t.Errorf("logs = %q, want them to mention %q", joined, tc.wantLogWord)
			}
		})
	}
}

// finish from a superseded run must not touch the current state.
func TestFinishIgnoresStaleRuns(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.run = 7
	m.state = State{Status: StatusRunning, PID: 99}
	m.mu.Unlock()

	m.finish(3, &exec.ExitError{ProcessState: fakeProcessState(t, 1)})

	st := m.State()
	if st.Status != StatusRunning || st.PID != 99 {
		t.Errorf("state = %+v, want the newer run left untouched", st)
	}
}

func TestManagerRejectsInvalidSpec(t *testing.T) {
	spec, dir := specForManager(t)
	spec.SessionTTL = "not-a-duration"
	m := NewManager()
	if _, err := m.startFake(spec, fakeServerScript(t, dir, 0), dir); err == nil {
		t.Fatal("expected Start to reject an invalid spec")
	}
	if st := m.State(); st.Status != StatusStopped {
		t.Errorf("status = %q, want the manager to stay stopped", st.Status)
	}
}

func TestManagerStopIsIdempotent(t *testing.T) {
	m := NewManager()
	if err := m.Stop(); err != nil {
		t.Errorf("Stop on an idle manager: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestLogRingReplaysAndFilters(t *testing.T) {
	r := newLogRing(3)
	for _, line := range []string{"a", "b", "c", "d"} {
		r.add(line)
	}
	got := r.since(0)
	if len(got) != 3 {
		t.Fatalf("ring kept %d lines, want 3", len(got))
	}
	if got[0].Text != "b" || got[2].Text != "d" {
		t.Errorf("ring contents = %v, want the newest three lines", got)
	}
	if seqs := r.since(got[1].Seq); len(seqs) != 1 || seqs[0].Text != "d" {
		t.Errorf("since() = %v, want only the line after the given sequence", seqs)
	}
}

func TestLogRingFansOut(t *testing.T) {
	r := newLogRing(10)
	head, ch := r.subscribe()
	defer r.detach(ch)
	r.add("hello")
	select {
	case line := <-ch:
		if line.Seq <= head || line.Text != "hello" {
			t.Errorf("received %+v, want a line after head %d", line, head)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive the line")
	}
}

func TestLogRingDropsSlowSubscribers(t *testing.T) {
	r := newLogRing(4096)
	_, ch := r.subscribe()
	// A subscriber that never reads must not block the writer.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			r.add("line")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("add blocked on a slow subscriber")
	}
	r.detach(ch)
}

func TestStripANSI(t *testing.T) {
	if got := StripANSI("\x1b[31merror\x1b[0m"); got != "error" {
		t.Errorf("StripANSI = %q, want \"error\"", got)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func waitForLines(t *testing.T, m *Manager, timeout time.Duration, needle string) []logLine {
	t.Helper()
	var lines []logLine
	waitFor(t, timeout, func() bool {
		lines = m.Logs().since(0)
		return strings.Contains(joinLines(lines), needle)
	})
	return lines
}

func joinLines(lines []logLine) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Text)
		b.WriteString("\n")
	}
	return b.String()
}
