SHELL := /bin/bash
MODULE := github.com/wangyaodreams-lab/underflow
BIN := bin/underflow
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

.PHONY: all build web wasm test test-race fuzz lint vet clean docker e2e fmt tidy cross

all: build

## build: compile the single binary (frontend assets must exist in web/dist)
build: web wasm
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/underflow

## build-go: compile without rebuilding the frontend (fast iteration)
build-go:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/underflow

## web: bundle the TypeScript frontend with esbuild
web:
	cd web && npm install --no-audit --no-fund && npm run build

## wasm: compile the crypto core to js/wasm and copy wasm_exec.js
wasm:
	mkdir -p web/dist
	GOOS=js GOARCH=wasm go build -trimpath -o web/dist/underflow.wasm ./wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/dist/wasm_exec.js

test:
	go test ./...

test-race:
	go test -race ./...

## test-wasm: run the js/wasm bridge tests under Node
wasm-test:
	GOOS=js GOARCH=wasm go test -exec "$$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./wasm/

## sec: static analysis and vulnerability scanning (tools must be installed)
sec:
	gofmt -l .
	go vet ./...
	staticcheck ./...
	gosec -quiet ./...
	govulncheck ./...

## fuzz: run crypto fuzz targets for 30s each
fuzz:
	go test ./crypto/ -run '^$$' -fuzz FuzzEnvelopeDecode -fuzztime 30s
	go test ./crypto/ -run '^$$' -fuzz FuzzBlobRoundTrip -fuzztime 30s

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

clean:
	rm -rf bin web/dist

cross:
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o /dev/null ./cmd/underflow
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o /dev/null ./cmd/underflow
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o /dev/null ./cmd/underflow

## test-all: full local verification (units, race, wasm, frontend)
test-all: test-race wasm-test
	cd web && npm ci && npm run typecheck

.PHONY: test-all sec wasm-test

docker:
	docker build -t underflow:$(VERSION) -f deployments/Dockerfile .

e2e:
	go test ./test/e2e/... -count=1
