package integration_test

import (
	"net/url"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
)

// urlURL existe so para deixar as assinaturas do jar de cookies legiveis.
type urlURL = url.URL

// hashDe calcula o sha256 de um arquivo pelo mesmo caminho que o orquestrador
// usa em producao.
func hashDe(path string) (string, error) {
	return baseline.HashFile(path)
}
