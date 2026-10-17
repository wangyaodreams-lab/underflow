package launcher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	state := filepath.Join(root, "state")
	fake := fakeServerScript(t, work, 0, "fake server starting")
	srv, err := NewServer(Options{
		WorkDir:  work,
		StateDir: state,
		Binary:   "underflow",
		Addr:     "127.0.0.1:18099",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Substitute the scripted stand-in for the real server binary and use a
	// short keepalive so the streaming test does not wait 15 seconds.
	srv.argv = func(Spec, string) []string { return fake }
	srv.keepalive = 250 * time.Millisecond
	t.Cleanup(func() { _ = srv.Manager().Stop() })
	return srv, work
}

func postJSON(t *testing.T, h http.Handler, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:18099"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s response: %v (%s)", path, err, rec.Body.String())
		}
	}
	return rec, out
}

func getJSON(t *testing.T, h http.Handler, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1:18099"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s response: %v (%s)", path, err, rec.Body.String())
		}
	}
	return rec, out
}

func TestBootstrapServesUIAndConfig(t *testing.T) {
	srv, work := newTestServer(t)

	// The page itself.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:18099"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content type = %q, want HTML", ct)
	}
	if rec.Body.Len() == 0 {
		t.Error("the launcher page is empty")
	}

	// The bootstrap payload.
	code, body := getJSON(t, srv.Handler(), "/api/bootstrap")
	if code.Code != http.StatusOK {
		t.Fatalf("GET /api/bootstrap = %d", code.Code)
	}
	for _, key := range []string{"spec", "result", "state", "pepper", "choices", "workDir", "binary"} {
		if _, ok := body[key]; !ok {
			t.Errorf("bootstrap payload is missing %q", key)
		}
	}
	result, _ := body["result"].(map[string]any)
	if result["ready"] != true {
		t.Errorf("default spec should be ready, got %v (issues %v)", result["ready"], result["issues"])
	}
	env, _ := result["env"].(map[string]any)
	if got := env["UF_DB_DSN"]; got != filepath.Join(work, "underflow.db") {
		t.Errorf("UF_DB_DSN = %v, want it resolved against the work dir", got)
	}
}

func TestSpecEndpointSavesAndRejects(t *testing.T) {
	srv, work := newTestServer(t)
	spec := DefaultSpec(work)
	spec.Listen = testAddr(t)
	spec.DBDSN = "saved.db"

	_, body := postJSON(t, srv.Handler(), "/api/spec", specRequest{Spec: spec})
	if body["saved"] != true {
		t.Fatalf("expected the spec to be saved, got %v", body)
	}

	// The saved state must be on disk and reloadable.
	reloaded, err := loadState(work, srv.stateDir)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if reloaded.DBDSN != "saved.db" {
		t.Errorf("persisted dsn = %q, want saved.db", reloaded.DBDSN)
	}

	// An invalid spec must be reported, not saved.
	bad := spec
	bad.SessionTTL = "nonsense"
	_, body = postJSON(t, srv.Handler(), "/api/spec", specRequest{Spec: bad})
	if body["saved"] != false {
		t.Errorf("an invalid spec must not be saved: %v", body)
	}
	res, _ := body["result"].(map[string]any)
	if res["ready"] != false {
		t.Error("expected ready=false for an invalid spec")
	}
	issues, _ := res["issues"].([]any)
	if len(issues) == 0 {
		t.Fatal("expected validation issues in the response")
	}
	first, _ := issues[0].(map[string]any)
	if first["field"] != "sessionTtl" {
		t.Errorf("first issue field = %v, want sessionTtl", first["field"])
	}
}

// The launcher must not be drivable from a page served elsewhere.
func TestOriginGuardRejectsForeignPages(t *testing.T) {
	srv, work := newTestServer(t)
	spec := DefaultSpec(work)

	send := func(host, origin string) int {
		data, _ := json.Marshal(specRequest{Spec: spec})
		req := httptest.NewRequest(http.MethodPost, "/api/start", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.Host = host
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send("evil.example.com:18099", ""); code != http.StatusForbidden {
		t.Errorf("non-loopback Host = %d, want 403", code)
	}
	if code := send("127.0.0.1:18099", "http://evil.example.com"); code != http.StatusForbidden {
		t.Errorf("foreign Origin = %d, want 403", code)
	}
	if code := send("127.0.0.1:18099", "http://127.0.0.1:18099"); code != http.StatusOK {
		t.Errorf("same-origin request = %d, want 200", code)
	}
	if code := send("localhost:18099", "http://localhost:18099"); code != http.StatusOK {
		t.Errorf("localhost origin = %d, want 200", code)
	}
	if code := send("127.0.0.1:1", ""); code != http.StatusForbidden {
		t.Errorf("wrong port = %d, want 403", code)
	}
}

func TestStartStopThroughAPI(t *testing.T) {
	srv, work := newTestServer(t)
	spec := DefaultSpec(work)
	spec.Listen = "127.0.0.1:0"
	spec.Local = false

	_, body := postJSON(t, srv.Handler(), "/api/start", specRequest{Spec: spec})
	if err, ok := body["error"]; ok && err != nil {
		t.Fatalf("start failed: %v", err)
	}
	state, _ := body["state"].(map[string]any)
	if state["pid"] == nil || state["pid"].(float64) <= 0 {
		t.Errorf("start should report the child pid, got %v", state["pid"])
	}
	if state["status"] != StatusStarting {
		t.Errorf("status = %v, want the launch to be reported as starting", state["status"])
	}

	// Stopping is accepted even after the scripted server has already exited.
	rec, body := postJSON(t, srv.Handler(), "/api/stop", struct{}{})
	if rec.Code != http.StatusOK {
		t.Fatalf("stop = %d", rec.Code)
	}
	state, _ = body["state"].(map[string]any)
	if state["status"] != StatusStopped && state["status"] != StatusExited {
		t.Errorf("status after stop = %v, want stopped or exited", state["status"])
	}
}

// A spec the server would reject must fail before a process is spawned.
func TestStartReportsSpawnFailure(t *testing.T) {
	srv, work := newTestServer(t)
	spec := DefaultSpec(work)
	spec.SessionTTL = "not-a-duration"

	_, body := postJSON(t, srv.Handler(), "/api/start", specRequest{Spec: spec})
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "session TTL") {
		t.Errorf("error = %q, want it to name the session TTL problem", msg)
	}
	state, _ := body["state"].(map[string]any)
	if state["status"] != StatusStopped {
		t.Errorf("status = %v, want the manager to stay stopped", state["status"])
	}
}

func TestLogStreamReplaysBufferedLines(t *testing.T) {
	srv, work := newTestServer(t)
	spec := DefaultSpec(work)
	spec.Listen = "127.0.0.1:0"
	spec.Local = false
	if _, body := postJSON(t, srv.Handler(), "/api/start", specRequest{Spec: spec}); body["error"] != nil {
		t.Fatalf("start: %v", body["error"])
	}
	waitFor(t, 10*time.Second, func() bool {
		return strings.Contains(joinLines(srv.Manager().Logs().since(0)), "fake server starting")
	})

	// Read the stream far enough to see the replayed backlog.
	req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	req.Host = "127.0.0.1:18099"
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	streamed := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(rec, req)
		close(streamed)
	}()

	waitFor(t, 5*time.Second, func() bool {
		return strings.Contains(rec.Body.String(), "fake server starting")
	})
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("content type = %q, want text/event-stream", ct)
	}
	if !strings.Contains(rec.Body.String(), "id: ") {
		t.Errorf("stream is missing SSE ids: %q", rec.Body.String())
	}
	cancel()
	<-streamed

	// A client that reconnects with Last-Event-ID must not re-receive lines.
	req2 := httptest.NewRequest(http.MethodGet, "/api/logs?after=999999", nil)
	req2.Host = "127.0.0.1:18099"
	ctx2, cancel2 := context.WithCancel(req2.Context())
	defer cancel2()
	req2 = req2.WithContext(ctx2)
	rec2 := httptest.NewRecorder()
	streamed2 := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(rec2, req2)
		close(streamed2)
	}()
	// The keepalive proves the response is established and the replay skipped.
	waitFor(t, 20*time.Second, func() bool {
		return strings.Contains(rec2.Body.String(), "keepalive")
	})
	if strings.Contains(rec2.Body.String(), "fake server starting") {
		t.Error("lines at or before the requested sequence must not be replayed")
	}
	cancel2()
	<-streamed2
}

func TestPepperEndpoint(t *testing.T) {
	srv, work := newTestServer(t)
	spec := DefaultSpec(work)
	spec.Listen = testAddr(t)
	spec.PepperFilePath = filepath.Join(work, "custom.pepper")

	_, body := postJSON(t, srv.Handler(), "/api/pepper", map[string]any{"spec": spec, "overwrite": false})
	pepper, _ := body["pepper"].(map[string]any)
	if pepper["exists"] != true {
		t.Fatalf("pepper was not created: %v", body)
	}
	if _, err := os.Stat(filepath.Join(work, "custom.pepper")); err != nil {
		t.Errorf("pepper file missing: %v", err)
	}

	// A second generation without overwrite must be refused.
	rec, body := postJSON(t, srv.Handler(), "/api/pepper", map[string]any{"spec": spec, "overwrite": false})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a protected pepper", rec.Code)
	}
	if _, ok := body["error"]; !ok {
		t.Errorf("expected an error body, got %v", body)
	}
}

func TestMethodsAreEnforced(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/start", nil)
	req.Host = "127.0.0.1:18099"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/start = %d, want 405", rec.Code)
	}
}

func TestStateEndpointReturnsResultAndPepper(t *testing.T) {
	srv, _ := newTestServer(t)
	rec, body := getJSON(t, srv.Handler(), "/api/state")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/state = %d", rec.Code)
	}
	for _, key := range []string{"state", "result", "pepper"} {
		if _, ok := body[key]; !ok {
			t.Errorf("state payload is missing %q", key)
		}
	}
	state, _ := body["state"].(map[string]any)
	if state["status"] != StatusStopped {
		t.Errorf("initial status = %v, want stopped", state["status"])
	}
}

// The SSE encoder must not emit raw newlines inside a data field.
func TestWriteSSEEscapesNewlines(t *testing.T) {
	rec := httptest.NewRecorder()
	if !writeSSE(rec, logLine{Seq: 7, Text: "first\r\nsecond"}) {
		t.Fatal("writeSSE reported failure")
	}
	got := rec.Body.String()
	if !strings.HasPrefix(got, "id: 7\ndata: first\\nsecond\n\n") {
		t.Errorf("unexpected SSE framing: %q", got)
	}

	// A reader must be able to consume the stream line by line.
	sc := bufio.NewScanner(strings.NewReader(got))
	lines := 0
	for sc.Scan() {
		lines++
	}
	if lines != 3 {
		t.Errorf("scanned %d lines, want 3 (id, data, blank)", lines)
	}
}
