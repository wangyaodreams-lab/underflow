package server

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/wangyaodreams-lab/underflow/internal/server/handlers"
	"github.com/wangyaodreams-lab/underflow/internal/server/middleware"
	"github.com/wangyaodreams-lab/underflow/web"
)

func (s *Server) router() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.RequestLogger(s.log))

	api := handlers.New(s.cfg, s.store, s.log)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/healthz", api.HandleHealthz)
		r.Get("/readyz", api.HandleReadyz)

		r.Route("/auth", func(r chi.Router) {
			r.Get("/kdf", api.HandleKDF)
			r.Post("/register", api.HandleRegister)
			r.Post("/login", api.HandleLogin)
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAuth(s.store, s.log))
				r.Use(middleware.CSRF)
				r.Post("/logout", api.HandleLogout)
				r.Post("/password", api.HandleChangePassword)
			})
		})

		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(s.store, s.log))
			r.Use(middleware.CSRF)
			r.Get("/user", api.HandleMe)
			r.Get("/vaults", api.HandleListVaults)
			r.Get("/vaults/{id}", api.HandleGetVault)
			r.Post("/vaults/{id}/items", api.HandleCreateItem)
			r.Get("/vaults/{id}/items/{itemId}", api.HandleGetItem)
			r.Put("/vaults/{id}/items/{itemId}", api.HandleUpdateItem)
			r.Delete("/vaults/{id}/items/{itemId}", api.HandleDeleteItem)
			r.Get("/sync", api.HandleSync)
		})
	})

	r.NotFound(s.webHandler().ServeHTTP)
	return r
}

// webHandler serves the embedded frontend, falling back to index.html for
// client-side routes.
func (s *Server) webHandler() http.Handler {
	sub, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		// Should never happen: embed guarantees the directory exists.
		panic("server: web dist missing: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if upath == "" || upath == "." {
			upath = "index.html"
		}
		if !strings.HasPrefix(upath, "api/") {
			if _, statErr := fs.Stat(sub, upath); statErr != nil {
				upath = "index.html"
				r = r.Clone(r.Context())
				r.URL.Path = "/"
			}
		}
		if ct := contentTypeFor(upath); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if strings.HasSuffix(upath, "underflow.wasm") || strings.HasSuffix(upath, "wasm_exec.js") {
			// wasm and its loader are versioned with the binary that serves them.
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".wasm"):
		return "application/wasm"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".json"):
		return "application/json; charset=utf-8"
	default:
		if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
			return ct
		}
		return ""
	}
}
