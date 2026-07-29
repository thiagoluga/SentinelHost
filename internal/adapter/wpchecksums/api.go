package wpchecksums

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DefaultAPIBase e a API publica de checksums do WordPress.org.
const DefaultAPIBase = "https://api.wordpress.org/core/checksums/1.0/"

// maxAPIBody limita a resposta. Um core tem alguns milhares de arquivos; 8 MiB
// e folgado e impede que uma resposta anomala estoure a memoria do orquestrador.
const maxAPIBody = 8 << 20

// ErrVersionUnknown indica que a API nao publica checksums para esta versao.
var ErrVersionUnknown = errors.New("a API nao publica checksums para esta versao")

// apiResponse e o formato da resposta.
//
// checksums vem como objeto quando a versao existe e como `false` quando nao
// existe — por isso o campo e json.RawMessage e nao um map direto.
type apiResponse struct {
	Checksums json.RawMessage `json:"checksums"`
}

// client busca checksums oficiais.
type client struct {
	base string
	http *http.Client
}

func newClient(base string) *client {
	if base == "" {
		base = DefaultAPIBase
	}
	return &client{
		base: base,
		http: &http.Client{
			// Hospedagem compartilhada as vezes tem saida de rede lenta ou
			// bloqueada. Um timeout curto e melhor que um ciclo pendurado:
			// sem rede, o adaptador se abstem e os outros engines seguem.
			Timeout: 20 * time.Second,
		},
	}
}

// fetch busca a resposta bruta da API.
//
// Devolve o corpo cru porque ELE e a saida bruta arquivada deste adaptador.
// Privacidade: a requisicao leva apenas versao e locale. Nenhum arquivo,
// caminho ou hash do usuario sai da hospedagem.
func (c *client) fetch(ctx context.Context, version, locale string) ([]byte, error) {
	if locale == "" {
		locale = "en_US"
	}
	u, err := url.Parse(c.base)
	if err != nil {
		return nil, fmt.Errorf("URL da API invalida: %w", err)
	}
	q := u.Query()
	q.Set("version", version)
	q.Set("locale", locale)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("montando requisicao: %w", err)
	}
	req.Header.Set("User-Agent", "SentinelHost (orquestrador de scanners; +https://github.com/thiagoluga/SentinelHost)")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("consultando a API de checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("a API de checksums respondeu %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return nil, fmt.Errorf("lendo resposta da API: %w", err)
	}
	return body, nil
}

// parseChecksums interpreta a resposta bruta.
func parseChecksums(body []byte) (map[string]string, error) {
	if len(body) == 0 {
		return nil, errors.New("resposta vazia da API de checksums")
	}
	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("resposta da API nao e JSON valido: %w", err)
	}
	if len(resp.Checksums) == 0 {
		return nil, errors.New("resposta da API sem o campo checksums")
	}

	// A API devolve `"checksums": false` para versao desconhecida. Tratar isso
	// como "nenhum arquivo diverge" declararia o core limpo por falta de
	// informacao — exatamente o erro que o Principio VI proibe.
	var asBool bool
	if err := json.Unmarshal(resp.Checksums, &asBool); err == nil {
		return nil, ErrVersionUnknown
	}

	var sums map[string]string
	if err := json.Unmarshal(resp.Checksums, &sums); err != nil {
		return nil, fmt.Errorf("campo checksums em formato inesperado: %w", err)
	}
	if len(sums) == 0 {
		return nil, ErrVersionUnknown
	}
	return sums, nil
}
