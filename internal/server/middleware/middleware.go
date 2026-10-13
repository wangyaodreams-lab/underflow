// Package middleware provides HTTP middleware for the Underflow API.
package middleware

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/wangyaodreams-lab/underflow/internal/auth"
	"github.com/wangyaodreams-lab/underflow/internal/model"
	"github.com/wangyaodreams-lab/underflow/internal/store"
)

type ctxKey int

const (
	ctxKeySession ctxKey = iota
	ctxKeyUser
	ctxKeyAuthSource
	ctxKeyRequestID
)

// AuthSource identifies how a request authenticated.
type AuthSource string

const (
	AuthCookie AuthSource = "cookie"
	AuthBearer AuthSource = "bearer"
)

// SessionCookieName is the web session cookie.
const SessionCookieName = "uf_session"

// CSRFCookieName is the double-submit CSRF cookie.
const CSRFCookieName = "uf_csrf"

// CSRFHeaderName is the header carrying the double-submit token.
const CSRFHeaderName = "X-UF-CSRF"

// WithSession stores the session in the context.
func WithSession(ctx context.Context, s model.Session) context.Context {
	return context.WithValue(ctx, ctxKeySession, s)
}

// SessionFrom retrieves the session from the context.
func SessionFrom(ctx context.Context) (model.Session, bool) {
	s, ok := ctx.Value(ctxKeySession).(model.Session)
	return s, ok
}

// WithUser stores the user in the context.
func WithUser(ctx context.Context, u model.User) context.Context {
	return context.WithValue(ctx, ctxKeyUser, u)
}

// UserFrom retrieves the user from the context.
func UserFrom(ctx context.Context) (model.User, bool) {
	u, ok := ctx.Value(ctxKeyUser).(model.User)
	return u, ok
}

// WithAuthSource stores how the request authenticated.
func WithAuthSource(ctx context.Context, s AuthSource) context.Context {
	return context.WithValue(ctx, ctxKeyAuthSource, s)
}

// AuthSourceFrom retrieves the authentication source.
func AuthSourceFrom(ctx context.Context) AuthSource {
	s, _ := ctx.Value(ctxKeyAuthSource).(AuthSource)
	return s
}

// WithRequestID stores a request id in the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// RequestIDFrom retrieves the request id.
func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(ctxKeyRequestID).(string)
	return s
}

// RequireAuth authenticates a request from either a Bearer token or the
// session cookie, loading the session and user into the context.
func RequireAuth(st store.Store, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""
			source := AuthBearer
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			} else if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
				token = c.Value
				source = AuthCookie
			}
			if token == "" {
				unauthorized(w)
				return
			}
			sess, err := st.SessionByTokenHash(r.Context(), auth.HashToken(token))
			if err != nil {
				unauthorized(w)
				return
			}
			now := time.Now().UTC()
			if now.After(sess.ExpiresAt) {
				_ = st.DeleteSession(r.Context(), sess.ID)
				unauthorized(w)
				return
			}
			user, err := st.UserByID(r.Context(), sess.UserID)
			if err != nil || user.Disabled {
				unauthorized(w)
				return
			}
			_ = st.TouchSession(r.Context(), sess.ID, now.UnixNano())

			ctx := WithSession(r.Context(), sess)
			ctx = WithUser(ctx, user)
			ctx = WithAuthSource(ctx, source)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CSRF enforces the double-submit cookie for cookie-authenticated,
// state-changing requests. Bearer-authenticated (CLI) requests are exempt.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) || AuthSourceFrom(r.Context()) != AuthCookie {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(CSRFCookieName)
		if err != nil || cookie.Value == "" {
			forbiddenCSRF(w)
			return
		}
		header := r.Header.Get(CSRFHeaderName)
		if subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) != 1 {
			forbiddenCSRF(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// SecurityHeaders sets defensive response headers. HSTS is only emitted over
// TLS.
func SecurityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; " +
		"style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// RequestLogger logs method, path, status and duration without ever logging
// request bodies (which may contain key material).
func RequestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"bytes", sw.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", ClientIP(r, nil),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// ClientIP returns the best-effort client IP, honouring X-Forwarded-For only
// when the immediate peer is within trustedProxies.
func ClientIP(r *http.Request, trustedProxies []string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(trustedProxies) == 0 {
		return host
	}
	trusted := false
	for _, p := range trustedProxies {
		if p == host {
			trusted = true
			break
		}
	}
	if !trusted {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	return host
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"authentication required"}}`))
}

func forbiddenCSRF(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":{"code":"csrf","message":"missing or invalid CSRF token"}}`))
}
