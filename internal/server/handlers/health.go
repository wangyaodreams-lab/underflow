package handlers

import "net/http"

// HandleHealthz is an unauthenticated liveness probe.
func (a *API) HandleHealthz(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// HandleReadyz checks datastore connectivity.
func (a *API) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.Ping(r.Context()); err != nil {
		a.writeErr(w, http.StatusServiceUnavailable, "not_ready", "datastore unavailable")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}
