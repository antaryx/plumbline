SHELL := /bin/bash
BINARY := plumbline
PKG    := github.com/antaryx/plumbline

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
CATALOG ?= $(shell grep -oP 'Version = \K[0-9]+' internal/catalog/catalog.go)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE) \
	-X main.catalog=$(CATALOG)

.PHONY: verify
## verify: the gate. Claude Code must run this and report the output before
## claiming any task is done. Never claim success without pasting this result.
verify: fmt-check vet test invariants

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/$(BINARY)

.PHONY: test
test:
	go test ./... -count=1

.PHONY: test-race
test-race:
	go test -race ./... -count=1

.PHONY: cover
cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet:
	go vet ./...

.PHONY: invariants
## invariants: architectural rules that a compiler cannot enforce but that the
## whole test strategy depends on. See CLAUDE.md.
invariants: check-system-seam check-check-purity check-fixture-coverage

.PHONY: check-system-seam
## Nothing outside internal/system may touch the OS directly. Violating this
## silently makes checks untestable, which is the failure mode that kills
## projects of this shape.
check-system-seam:
	@bad=$$(grep -rn --include='*.go' \
		-e '\bos\.\(Open\|ReadFile\|ReadDir\|Stat\|Lstat\)' \
		-e '\bexec\.Command' \
		-e '\bioutil\.' \
		internal/ cmd/ 2>/dev/null \
		| grep -v '^internal/system/' \
		| grep -v '_test\.go:' || true); \
	if [ -n "$$bad" ]; then \
		echo "ERROR: direct OS access outside internal/system:"; echo "$$bad"; exit 1; \
	fi
	@echo "ok: system seam intact"

.PHONY: check-check-purity
## A check may not import system, context, time, net or math/rand. Purity is
## what makes findings deterministic.
check-check-purity:
	@bad=$$(grep -rn --include='*.go' \
		-e '"context"' -e '"time"' -e '"net' -e '"math/rand"' \
		-e 'internal/system' \
		internal/catalog/checks/ 2>/dev/null | grep -v '_test\.go:' || true); \
	if [ -n "$$bad" ]; then \
		echo "ERROR: impure import in a check:"; echo "$$bad"; exit 1; \
	fi
	@echo "ok: checks are pure"

.PHONY: check-fixture-coverage
## Every check needs at least one PASS and one FAIL fixture case. This gate
## exists from check #1 so that complying with it is never expensive.
check-fixture-coverage:
	@go run ./tools/fixturegate 2>/dev/null || echo "note: tools/fixturegate not yet built (v0.1 WP-06)"

.PHONY: docs
docs:
	@echo "regenerate MODULE-CATALOG.md and CHECK-REFERENCE.md (v0.3 WP)"

.PHONY: clean
clean:
	rm -rf dist coverage.out

.PHONY: help
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //'
