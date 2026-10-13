package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/wangyaodreams-lab/underflow/internal/model"
	"github.com/wangyaodreams-lab/underflow/internal/server/middleware"
)

type createItemRequest struct {
	ID   string `json:"id"`
	Blob string `json:"blob"`
}

type updateItemRequest struct {
	Blob         string `json:"blob"`
	BaseRevision int64  `json:"baseRevision"`
}

func toItemDTO(it model.Item) itemDTO {
	return itemDTO{
		ID:        it.ID,
		VaultID:   it.VaultID,
		Revision:  it.Revision,
		Blob:      b64encode(it.Blob),
		Deleted:   it.Deleted,
		UpdatedAt: it.UpdatedAt.UnixNano(),
	}
}

// HandleCreateItem creates a new encrypted item. The client chooses the item
// id so it can derive the per-item key and AAD before uploading.
func (a *API) HandleCreateItem(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var req createItemRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	if req.ID == "" {
		a.badRequest(w, "item id is required")
		return
	}
	blob, err := b64decode(req.Blob)
	if err != nil || len(blob) == 0 {
		a.badRequest(w, "blob is required")
		return
	}
	it, err := a.Store.UpsertItem(r.Context(), user.ID, model.Item{
		ID: req.ID, VaultID: chi.URLParam(r, "id"), Blob: blob,
	}, 0)
	if err != nil {
		a.mapStoreErr(w, err)
		return
	}
	a.writeJSON(w, http.StatusCreated, toItemDTO(it))
}

// HandleUpdateItem replaces an item's ciphertext using optimistic concurrency.
func (a *API) HandleUpdateItem(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var req updateItemRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	blob, err := b64decode(req.Blob)
	if err != nil || len(blob) == 0 {
		a.badRequest(w, "blob is required")
		return
	}
	it, err := a.Store.UpsertItem(r.Context(), user.ID, model.Item{
		ID: chi.URLParam(r, "itemId"), VaultID: chi.URLParam(r, "id"), Blob: blob,
	}, req.BaseRevision)
	if err != nil {
		a.mapStoreErr(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toItemDTO(it))
}

// HandleDeleteItem tombstones an item.
func (a *API) HandleDeleteItem(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	baseRev, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
	if err != nil {
		a.badRequest(w, "revision query parameter is required")
		return
	}
	it, err := a.Store.DeleteItem(r.Context(), user.ID, chi.URLParam(r, "id"), chi.URLParam(r, "itemId"), baseRev)
	if err != nil {
		a.mapStoreErr(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toItemDTO(it))
}

// HandleGetItem returns a single item.
func (a *API) HandleGetItem(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	it, err := a.Store.GetItem(r.Context(), user.ID, chi.URLParam(r, "id"), chi.URLParam(r, "itemId"))
	if err != nil {
		a.mapStoreErr(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toItemDTO(it))
}
