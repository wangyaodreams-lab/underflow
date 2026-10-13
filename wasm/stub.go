//go:build !(js && wasm)

// This stub keeps `go build ./...` and `go vet ./...` working on non-wasm
// platforms. The real entry point lives in main_js.go.
package main

func main() {}
