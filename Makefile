SHELL := /bin/bash
BINARY := plumbline
PKG    := github.com/antaryx/plumbline

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
CATALOG ?= $(shell grep -oP 'Version = \K[0-9]+' internal/catalog/catalog.go)

## The catalog version is deliberately not stamped: it is compiled in, and
## asking the catalog is the only answer that cannot drift from what runs.
LDFLAGS := -s -w \
	-X main.buildVersion=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

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
##
## The pattern matches an import *line* rather than any occurrence of the
## quoted path, because a check's own data is full of these words. A sysctl key
## is called net.ipv4.conf.all.rp_filter, a tag is called "network", and
## SERVICES-0003 is about clock synchronisation so its tags include "time".
## Matching those reports violations that are not ones, and a gate that cries
## wolf is a gate somebody eventually silences -- which is a far worse outcome
## than the one it was guarding against.
##
## What makes the line form unambiguous is that an import ends after the quoted
## path, while a slice element ends with a comma that gofmt will not remove. An
## optional leading identifier covers the aliased, blank and dot forms
## (t "time", _ "net/http", . "context"), and the optional 'import' keyword
## covers the single-line declaration.
##
## internal/system is still matched anywhere in the line: it is a path that
## appears in no check's data, and a mention of it in a check is worth reading
## whether or not it is an import.
IMPURE := ^[[:space:]]*(import[[:space:]]+)?([A-Za-z0-9_.]+[[:space:]]+)?"(context|time|net|net/[^"]*|math/rand)"[[:space:]]*(//.*)?$$
check-check-purity:
	@bad=$$(grep -rEn --include='*.go' -e '$(IMPURE)' -e 'internal/system' \
		internal/catalog/checks/ 2>/dev/null | grep -v '_test\.go:' || true); \
	if [ -n "$$bad" ]; then \
		echo "ERROR: impure import in a check:"; echo "$$bad"; exit 1; \
	fi
	@echo "ok: checks are pure"

.PHONY: check-fixture-coverage
## Every check needs at least one PASS and one FAIL fixture case. This gate
## exists from check #1 so that complying with it is never expensive.
check-fixture-coverage:
	@go run ./tools/fixturegate

.PHONY: golden-diff
## golden-diff: report which golden bundles no longer evaluate to their
## expectation. Read-only — it writes nothing and names the first check that
## moved on each bundle. Run it after any catalog change: a change that moves a
## verdict on eight recorded distributions when you expected one is telling you
## something before your users do (docs/FIXTURES.md §6).
golden-diff:
	go test ./internal/cli/ -run TestGolden -count=1

.PHONY: golden-update
## golden-update: rewrite testdata/bundles/*.expected.json from the current
## catalog, then show what changed.
##
## **This is a reviewed act, not a convenience.** A PR that runs it without
## explaining every moved verdict in the description should be refused: this is
## the one command that can silently rewrite the definition of PASS across the
## whole recorded corpus. The hand-typed counts in internal/cli/golden_test.go
## are not regenerated, and are what force somebody to state the new numbers.
##
## Re-recording the bundles themselves is testdata/bundles/record.sh, which
## needs docker and is never run by CI.
golden-update:
	go test ./internal/cli/ -run TestGolden -count=1 -update
	@git --no-pager diff --stat -- testdata/bundles || true
	@echo "read the diff: git diff testdata/bundles"

.PHONY: docs
docs:
	@echo "regenerate MODULE-CATALOG.md and CHECK-REFERENCE.md (v0.3 WP)"

.PHONY: clean
clean:
	rm -rf dist coverage.out

.PHONY: help
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //'
