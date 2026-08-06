BINARY  := sentinelhost
PKG     := ./cmd/sentinelhost
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(DATE)

# CGO_ENABLED=0 is not negotiable: the binary has to be static to run on a shared
# hosting account with no compatible glibc (Principle VII).
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build test test-short test-linux lint fmt vet tidy clean release install-lint doctor

all: lint test build

build:
	$(GOBUILD) -o dist/$(BINARY) $(PKG)

release: clean
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o dist/$(BINARY)-linux-amd64 $(PKG)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o dist/$(BINARY)-linux-arm64 $(PKG)
	cd dist && sha256sum $(BINARY)-linux-* > SHA256SUMS

test:
	go test ./... -count=1

test-short:
	go test ./... -short -count=1

# The suite on Linux, from a Windows workstation.
#
# `make test` on Windows silently skips every test that depends on permissions, hard
# links, symlinks, or a filename containing a newline — correctly, with a reason, and
# invisibly: without -v a skip and a pass are the same line. Until now those tests only
# ever ran in CI, so between a commit and a push there was no way to know.
#
# This is not `validate-engines`. That one installs yara, maldet, PHP and a real WordPress
# to check what the ENGINES do, takes minutes and needs the network. This asks the smaller
# question — does our own code behave on Linux — and is meant to be run often.
test-linux:
	bash docker/run-suite-on-linux.sh

# The slow tests (SC-002: 20k files) stay out of -short.
test-race:
	go test ./... -race -count=1

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf dist/

install-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Validation of the REAL engines on a simulated hosting account (Debian + PHP +
# yara, a non-root user). It is the only way to exercise the command lines the
# adapters assemble: the automated suite only tests Probe() and Parse().
.PHONY: validate-engines
validate-engines:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o dist/sentinelhost-linux-amd64 $(PKG)
	docker build -f docker/Dockerfile.validation -t sentinelhost-validation .
	docker run --rm sentinelhost-validation
