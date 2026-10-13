// Package handlers implements the Underflow HTTP API. It is zero-knowledge:
// request and response payloads contain only ciphertext and public key
// derivation parameters.
package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/auth"
	"github.com/wangyaodreams-lab/underflow/internal/config"
	"github.com/wangyaodreams-lab/underflow/internal/store"
)

// API holds the dependencies shared by all handlers.
type API struct {
	Cfg             config.Config
	Store           store.Store
	Log             *slog.Logger
	LoginLimiter    *auth.Limiter
	RegisterLimiter *auth.Limiter
	Now             func() time.Time
}

// New returns an API with sensible defaults.
func New(cfg config.Config, st store.Store, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	return &API{
		Cfg:             cfg,
		Store:           st,
		Log:             log,
		LoginLimiter:    auth.NewLimiter(10, 5*time.Minute),
		RegisterLimiter: auth.NewLimiter(5, time.Hour),
		Now:             func() time.Time { return time.Now().UTC() },
	}
}

// --- DTOs ---

type kdfDTO struct {
	ID   uint8  `json:"id"`
	M    uint32 `json:"m"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
	Salt string `json:"salt"` // base64, 16 bytes
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type itemDTO struct {
	ID        string `json:"id"`
	VaultID   string `json:"vaultId"`
	Revision  int64  `json:"revision"`
	Blob      string `json:"blob"`
	Deleted   bool   `json:"deleted"`
	UpdatedAt int64  `json:"updatedAt"`
}

type vaultDTO struct {
	ID                string `json:"id"`
	Alg               uint8  `json:"alg"`
	NameEnc           string `json:"nameEnc"`
	ProtectedVaultKey string `json:"protectedVaultKey"`
	Revision          int64  `json:"revision"`
	UpdatedAt         int64  `json:"updatedAt"`
}

// --- helpers ---

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (a *API) writeErr(w http.ResponseWriter, status int, code, msg string) {
	a.writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: msg}})
}

func (a *API) badRequest(w http.ResponseWriter, msg string) {
	a.writeErr(w, http.StatusBadRequest, "bad_request", msg)
}

func (a *API) serverError(w http.ResponseWriter, err error) {
	a.Log.Error("internal error", "error", err)
	a.writeErr(w, http.StatusInternalServerError, "internal", "internal server error")
}

// decodeJSON reads and decodes a JSON body with a size limit and strictness.
func (a *API) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, a.Cfg.MaxRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		a.badRequest(w, "invalid JSON body")
		return false
	}
	return true
}

func (k kdfDTO) toParams() (crypto.KDFParams, error) {
	var p crypto.KDFParams
	salt, err := b64decode(k.Salt)
	if err != nil {
		return p, fmt.Errorf("invalid salt encoding")
	}
	if len(salt) != 16 {
		return p, fmt.Errorf("salt must be 16 bytes")
	}
	p.ID, p.M, p.T, p.P = k.ID, k.M, k.T, k.P
	copy(p.Salt[:], salt)
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func paramsToDTO(p crypto.KDFParams) kdfDTO {
	return kdfDTO{ID: p.ID, M: p.M, T: p.T, P: p.P, Salt: b64encode(p.Salt[:])}
}

func b64encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func b64decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// fakeSalt produces a deterministic salt for unknown accounts so that the
// pre-login endpoint does not trivially disclose which emails are registered.
func (a *API) fakeSalt(email string) []byte {
	m := hmac.New(sha256.New, a.Cfg.ServerPepper)
	m.Write([]byte("kdf:" + strings.ToLower(strings.TrimSpace(email))))
	sum := m.Sum(nil)
	return sum[:16]
}

// registrationAllowed enforces the configured registration mode.
func (a *API) registrationAllowed(r *http.Request) bool {
	switch a.Cfg.Registration {
	case config.RegistrationOpen:
		return true
	case config.RegistrationInvite:
		return a.Cfg.InviteCode != "" && constantTimeEqual(r.Header.Get("X-UF-Invite"), a.Cfg.InviteCode)
	default:
		return false
	}
}

func constantTimeEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// mapStoreErr converts store errors into HTTP responses.
func (a *API) mapStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		a.writeErr(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, store.ErrConflict):
		a.writeErr(w, http.StatusConflict, "revision_conflict", "item was modified concurrently")
	case errors.Is(err, store.ErrEmailTaken):
		a.writeErr(w, http.StatusConflict, "email_taken", "email already registered")
	default:
		a.serverError(w, err)
	}
}
