package handlers

import (
	"net/http"
	"strconv"

	"github.com/wangyaodreams-lab/underflow/internal/server/middleware"
)

// HandleSync returns items changed after ?since=<revision> plus the current
// global revision.
func (a *API) HandleSync(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			a.badRequest(w, "invalid since parameter")
			return
		}
		since = v
	}
	items, rev, err := a.Store.Sync(r.Context(), user.ID, since)
	if err != nil {
		a.serverError(w, err)
		return
	}
	out := make([]itemDTO, 0, len(items))
	for _, it := range items {
		out = append(out, toItemDTO(it))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": out, "revision": rev})
}
