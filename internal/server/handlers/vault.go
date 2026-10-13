package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/wangyaodreams-lab/underflow/internal/model"
	"github.com/wangyaodreams-lab/underflow/internal/server/middleware"
)

func toVaultDTO(v model.Vault) vaultDTO {
	return vaultDTO{
		ID:                v.ID,
		Alg:               v.Alg,
		NameEnc:           b64encode(v.NameEnc),
		ProtectedVaultKey: b64encode(v.ProtectedVaultKey),
		Revision:          v.Revision,
		UpdatedAt:         v.UpdatedAt.UnixNano(),
	}
}

// HandleListVaults returns the authenticated user's vaults.
func (a *API) HandleListVaults(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	vaults, err := a.Store.ListVaults(r.Context(), user.ID)
	if err != nil {
		a.serverError(w, err)
		return
	}
	out := make([]vaultDTO, 0, len(vaults))
	for _, v := range vaults {
		out = append(out, toVaultDTO(v))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"vaults": out})
}

// HandleGetVault returns a single vault owned by the authenticated user.
func (a *API) HandleGetVault(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	v, err := a.Store.GetVault(r.Context(), user.ID, chi.URLParam(r, "id"))
	if err != nil {
		a.mapStoreErr(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toVaultDTO(v))
}
