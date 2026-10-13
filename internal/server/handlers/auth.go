package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/auth"
	"github.com/wangyaodreams-lab/underflow/internal/model"
	"github.com/wangyaodreams-lab/underflow/internal/server/middleware"
	"github.com/wangyaodreams-lab/underflow/internal/store"
)

type registerRequest struct {
	Email             string `json:"email"`
	KDF               kdfDTO `json:"kdf"`
	AuthKey           string `json:"authKey"` // base64, 32 bytes
	VaultID           string `json:"vaultId"`
	Alg               uint8  `json:"alg"`
	VaultNameEnc      string `json:"vaultNameEnc"`
	ProtectedVaultKey string `json:"protectedVaultKey"`
}

type loginRequest struct {
	Email   string `json:"email"`
	AuthKey string `json:"authKey"` // base64, 32 bytes
}

type sessionResponse struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	KDF    kdfDTO `json:"kdf"`
	Token  string `json:"token,omitempty"`
	CSRF   string `json:"csrf,omitempty"`
}

type changePasswordRequest struct {
	KDF     kdfDTO            `json:"kdf"`
	AuthKey string            `json:"authKey"` // base64, 32 bytes
	Vaults  []vaultKeyRequest `json:"vaults"`
}

type vaultKeyRequest struct {
	ID                string `json:"id"`
	Alg               uint8  `json:"alg"`
	ProtectedVaultKey string `json:"protectedVaultKey"`
}

// HandleKDF returns the KDF parameters for an email. Unknown emails receive a
// deterministic decoy so registration status is not disclosed.
func (a *API) HandleKDF(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	if email == "" {
		a.badRequest(w, "email is required")
		return
	}
	user, err := a.Store.UserByEmail(r.Context(), email)
	switch {
	case err == nil:
		a.writeJSON(w, http.StatusOK, map[string]any{"kdf": paramsToDTO(crypto.KDFParams{
			ID: user.KDFID, M: user.KDFM, T: user.KDFT, P: user.KDFP,
			Salt: saltArray(user.KDFSalt),
		})})
	case errors.Is(err, store.ErrNotFound):
		p, _ := crypto.ParamsForProfile(crypto.Profile(a.Cfg.Argon2Profile), saltArray(a.fakeSalt(email)))
		a.writeJSON(w, http.StatusOK, map[string]any{"kdf": paramsToDTO(p)})
	default:
		a.serverError(w, err)
	}
}

func saltArray(b []byte) [16]byte {
	var s [16]byte
	copy(s[:], b)
	return s
}

// HandleRegister creates an account and its default vault.
func (a *API) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if !a.registrationAllowed(r) {
		a.writeErr(w, http.StatusForbidden, "registration_closed", "registration is not allowed")
		return
	}
	if !a.RegisterLimiter.Allow(middleware.ClientIP(r, a.Cfg.TrustedProxies)) {
		a.writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try later")
		return
	}
	var req registerRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(email) {
		a.badRequest(w, "invalid email")
		return
	}
	params, err := req.KDF.toParams()
	if err != nil {
		a.badRequest(w, "invalid KDF parameters")
		return
	}
	authKeyBytes, err := b64decode(req.AuthKey)
	if err != nil || len(authKeyBytes) != 32 {
		a.badRequest(w, "authKey must be 32 bytes of base64")
		return
	}
	var authKey [32]byte
	copy(authKey[:], authKeyBytes)
	verifier := crypto.ComputeVerifier(a.Cfg.ServerPepper, authKey)
	protKey, err := b64decode(req.ProtectedVaultKey)
	if err != nil || len(protKey) == 0 {
		a.badRequest(w, "protectedVaultKey is required")
		return
	}
	nameEnc, err := b64decode(req.VaultNameEnc)
	if err != nil || len(nameEnc) == 0 {
		a.badRequest(w, "vaultNameEnc is required")
		return
	}
	if req.VaultID == "" {
		a.badRequest(w, "vaultId is required")
		return
	}
	if req.Alg != crypto.AlgXChaCha20Poly1305 && req.Alg != crypto.AlgAES256GCM {
		a.badRequest(w, "unsupported algorithm")
		return
	}

	now := a.Now()
	user := model.User{
		ID: uuid.NewString(), Email: email,
		KDFID: params.ID, KDFM: params.M, KDFT: params.T, KDFP: params.P,
		KDFSalt: params.Salt[:], Verifier: verifier, CreatedAt: now,
	}
	vault := model.Vault{
		ID: req.VaultID, OwnerID: user.ID,
		NameEnc: nameEnc, ProtectedVaultKey: protKey, Alg: req.Alg,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.Store.CreateUser(r.Context(), user); err != nil {
		a.mapStoreErr(w, err)
		return
	}
	if err := a.Store.CreateVault(r.Context(), vault); err != nil {
		a.mapStoreErr(w, err)
		return
	}
	a.audit(r, user.ID, "register")
	a.issueSession(w, r, user)
}

// HandleLogin verifies the derived AuthKey and opens a session.
func (a *API) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ip := middleware.ClientIP(r, a.Cfg.TrustedProxies)
	if !a.LoginLimiter.Allow(ip+"|"+email) || !a.LoginLimiter.Allow("ip|"+ip) {
		a.writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try later")
		return
	}
	authKey, err := b64decode(req.AuthKey)
	if err != nil || len(authKey) != 32 {
		a.badRequest(w, "authKey must be 32 bytes of base64")
		return
	}
	user, err := a.Store.UserByEmail(r.Context(), email)
	if err != nil || user.Disabled {
		a.writeErr(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or master password")
		return
	}
	var ak [32]byte
	copy(ak[:], authKey)
	if !crypto.Verify(ak, a.Cfg.ServerPepper, user.Verifier) {
		a.audit(r, user.ID, "login_failed")
		a.writeErr(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or master password")
		return
	}
	a.audit(r, user.ID, "login")
	a.issueSession(w, r, user)
}

// HandleLogout revokes the current session.
func (a *API) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := middleware.SessionFrom(r.Context()); ok {
		_ = a.Store.DeleteSession(r.Context(), sess.ID)
		a.audit(r, sess.UserID, "logout")
	}
	a.clearCookies(w, r)
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// HandleMe returns the authenticated account metadata.
func (a *API) HandleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	a.writeJSON(w, http.StatusOK, sessionResponse{
		UserID: user.ID,
		Email:  user.Email,
		KDF: paramsToDTO(crypto.KDFParams{
			ID: user.KDFID, M: user.KDFM, T: user.KDFT, P: user.KDFP,
			Salt: saltArray(user.KDFSalt),
		}),
	})
}

// HandleChangePassword re-wraps vault keys under a new master key and revokes
// all other sessions.
func (a *API) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFrom(r.Context())
	if !ok {
		a.writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var req changePasswordRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	params, err := req.KDF.toParams()
	if err != nil {
		a.badRequest(w, "invalid KDF parameters")
		return
	}
	authKeyBytes, err := b64decode(req.AuthKey)
	if err != nil || len(authKeyBytes) != 32 {
		a.badRequest(w, "authKey must be 32 bytes of base64")
		return
	}
	var newAuthKey [32]byte
	copy(newAuthKey[:], authKeyBytes)
	verifier := crypto.ComputeVerifier(a.Cfg.ServerPepper, newAuthKey)
	if len(req.Vaults) == 0 {
		a.badRequest(w, "at least one vault key is required")
		return
	}
	// Validate vault rewraps before mutating anything.
	type rewrap struct {
		id  string
		alg uint8
		key []byte
	}
	var rewraps []rewrap
	for _, v := range req.Vaults {
		key, err := b64decode(v.ProtectedVaultKey)
		if err != nil || len(key) == 0 {
			a.badRequest(w, "invalid protectedVaultKey")
			return
		}
		if v.Alg != crypto.AlgXChaCha20Poly1305 && v.Alg != crypto.AlgAES256GCM {
			a.badRequest(w, "unsupported algorithm")
			return
		}
		if _, err := a.Store.GetVault(r.Context(), user.ID, v.ID); err != nil {
			a.mapStoreErr(w, err)
			return
		}
		rewraps = append(rewraps, rewrap{id: v.ID, alg: v.Alg, key: key})
	}

	if err := a.Store.UpdateUserKDF(r.Context(), user.ID, params.ID, params.M, params.T, params.P, params.Salt[:], verifier); err != nil {
		a.mapStoreErr(w, err)
		return
	}
	for _, rw := range rewraps {
		if err := a.Store.UpdateVaultKey(r.Context(), user.ID, rw.id, rw.alg, rw.key); err != nil {
			a.mapStoreErr(w, err)
			return
		}
	}
	if sess, ok := middleware.SessionFrom(r.Context()); ok {
		_, _ = a.Store.DeleteSessionsForUser(r.Context(), user.ID, sess.ID)
	} else {
		_, _ = a.Store.DeleteSessionsForUser(r.Context(), user.ID, "")
	}
	a.audit(r, user.ID, "password_changed")
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- session plumbing ---

func (a *API) issueSession(w http.ResponseWriter, r *http.Request, user model.User) {
	now := a.Now()
	token, hash, err := auth.NewToken()
	if err != nil {
		a.serverError(w, err)
		return
	}
	csrf, err := auth.NewCSRF()
	if err != nil {
		a.serverError(w, err)
		return
	}
	sess := model.Session{
		ID: uuid.NewString(), UserID: user.ID, TokenHash: hash,
		DeviceLabel: r.Header.Get("X-UF-Device"),
		CreatedAt:   now, ExpiresAt: now.Add(a.Cfg.SessionTTL), LastSeenAt: now,
	}
	if err := a.Store.CreateSession(r.Context(), sess); err != nil {
		a.serverError(w, err)
		return
	}
	resp := sessionResponse{
		UserID: user.ID, Email: user.Email,
		KDF: paramsToDTO(crypto.KDFParams{
			ID: user.KDFID, M: user.KDFM, T: user.KDFT, P: user.KDFP,
			Salt: saltArray(user.KDFSalt),
		}),
	}
	if isCLI(r) {
		resp.Token = token
		resp.CSRF = csrf
	} else {
		a.setCookies(w, r, token, csrf)
	}
	a.writeJSON(w, http.StatusOK, resp)
}

func (a *API) setCookies(w http.ResponseWriter, r *http.Request, token, csrf string) {
	secure := requestIsSecure(r)
	maxAge := int(a.Cfg.SessionTTL.Seconds())
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the request scheme; HttpOnly and SameSite=Strict are always set.
		Name: middleware.SessionCookieName, Value: token, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- see above; this cookie is intentionally readable by JS for CSRF.
		Name: middleware.CSRFCookieName, Value: csrf, Path: "/",
		HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
}

func (a *API) clearCookies(w http.ResponseWriter, r *http.Request) {
	secure := requestIsSecure(r)
	for _, name := range []string{middleware.SessionCookieName, middleware.CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the request scheme; HttpOnly and SameSite=Strict are always set.
			Name: name, Value: "", Path: "/",
			HttpOnly: name == middleware.SessionCookieName, Secure: secure,
			SameSite: http.SameSiteStrictMode, MaxAge: -1,
		})
	}
}

// requestIsSecure reports whether the client connection is HTTPS, either
// directly or via a TLS-terminating reverse proxy. Trusting
// X-Forwarded-Proto here can only make the cookie *more* restrictive, so it is
// safe even without a trusted-proxy allowlist.
func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		first := strings.TrimSpace(strings.Split(xfp, ",")[0])
		return strings.EqualFold(first, "https")
	}
	return false
}

func isCLI(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("X-UF-Client"), "cli")
}

func (a *API) audit(r *http.Request, userID, action string) {
	e := model.AuditEntry{
		ID: uuid.NewString(), UserID: userID, Action: action,
		IP: middleware.ClientIP(r, a.Cfg.TrustedProxies),
		UA: truncate(r.UserAgent(), 512), At: a.Now(),
	}
	if err := a.Store.AddAudit(r.Context(), e); err != nil {
		a.Log.Warn("audit write failed", "error", err, "action", action)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func validEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n") && len(s) <= 320
}
