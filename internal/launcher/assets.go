package launcher

import (
	"embed"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// dist holds the launcher's own single-page UI. A placeholder index.html is
// committed so that `go build` always succeeds; `npm run build` in web/
// replaces it with the real page. This mirrors the web/dist convention used
// by the server.
//
//go:embed all:dist
var dist embed.FS

// readAsset returns a launcher asset from the embedded build.
func readAsset(name string) ([]byte, error) {
	return dist.ReadFile("dist/" + name)
}

// MaterializeAssets writes the embedded launcher UI into dir and returns the
// path of index.html. Tests use it to exercise the real page.
func MaterializeAssets(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	entries, err := fs.ReadDir(dist, "dist")
	if err != nil {
		return "", err
	}
	out := ""
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := readAsset(e.Name())
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			return "", err
		}
		if e.Name() == "index.html" {
			out = filepath.Join(dir, e.Name())
		}
	}
	if out == "" {
		return "", errors.New("launcher assets contain no index.html")
	}
	return out, nil
}
