// Package web embeds the built frontend assets so the server ships as a single
// binary. Source lives in web/; `make web` produces web/dist.
package web

import "embed"

// Dist contains the built frontend (index.html, app.js, app.css,
// underflow.wasm, wasm_exec.js). A placeholder index.html is committed so the
// binary always builds even before the frontend is compiled.
//
//go:embed all:dist
var Dist embed.FS
