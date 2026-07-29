BINARY  := sentinelhost
PKG     := ./cmd/sentinelhost
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(DATE)

# CGO_ENABLED=0 nao e negociavel: o binario precisa ser estatico para rodar
# numa conta de hospedagem compartilhada sem glibc compativel (Principio VII).
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build test test-short lint fmt vet tidy clean release install-lint doctor

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

# Testes lentos (SC-002: 20k arquivos) ficam fora do -short.
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

# Validacao dos engines REAIS numa hospedagem simulada (Debian + PHP + yara,
# usuario sem root). E o unico jeito de exercitar as linhas de comando que os
# adaptadores montam: a suite automatizada so testa Probe() e Parse().
.PHONY: validar-engines
validar-engines:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o dist/sentinelhost-linux-amd64 $(PKG)
	docker build -f docker/Dockerfile.validacao -t sentinelhost-validacao .
	docker run --rm sentinelhost-validacao
