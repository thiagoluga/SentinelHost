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
	// pluginsBase sobrepoe a API de plugins nos testes. Vazio usa a oficial.
	pluginsBase string
	http        *http.Client
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

// ErrPluginSemChecksum indica que a API nao publica checksums para aquele
// plugin/versao.
//
// E o caso NORMAL para plugin comercial, plugin proprio, ou versao que saiu do
// diretorio oficial. Nao e falha e nao e achado: o adaptador se abstem sobre
// aquele plugin. Tratar ausencia de dado como ausencia de problema seria
// declarar limpo o que ninguem conferiu.
var ErrPluginSemChecksum = errors.New("a API nao publica checksums para este plugin nesta versao")

// pluginFileSums sao os hashes que a API publica por arquivo de plugin.
//
// Ao contrario do core, que so publica MD5, aqui vem os dois — e sao ARRAYS,
// porque um mesmo caminho pode ter variantes aceitas (arquivo com CRLF e com
// LF, por exemplo). Basta bater com uma.
type pluginFileSums struct {
	MD5    []string `json:"md5"`
	SHA256 []string `json:"sha256"`
}

// pluginChecksumsResponse e o formato de downloads.wordpress.org/plugin-checksums.
type pluginChecksumsResponse struct {
	Plugin  string                    `json:"plugin"`
	Version string                    `json:"version"`
	Files   map[string]pluginFileSums `json:"files"`
}

// fetchPlugin busca os checksums de um plugin numa versao.
//
// Privacidade: a requisicao leva apenas o slug e a versao — que e exatamente o
// que a constituicao autoriza ("hashes e slugs de versao"). Nenhum caminho ou
// conteudo do usuario sai da hospedagem.
func (c *client) fetchPlugin(ctx context.Context, slug, version string) ([]byte, error) {
	if slug == "" || version == "" {
		return nil, ErrPluginSemChecksum
	}
	// O slug vem de um nome de diretorio no disco do usuario. PathEscape
	// impede que um diretorio chamado `../algo` monte uma URL para outro
	// lugar da API.
	u := c.pluginBase() + url.PathEscape(slug) + "/" + url.PathEscape(version) + ".json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("montando requisicao: %w", err)
	}
	req.Header.Set("User-Agent", "SentinelHost (orquestrador de scanners; +https://github.com/thiagoluga/SentinelHost)")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("consultando checksums do plugin %s: %w", slug, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 404 e a resposta esperada para plugin fora do diretorio oficial.
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s %s", ErrPluginSemChecksum, slug, version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("a API de checksums do plugin %s respondeu %s", slug, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return nil, fmt.Errorf("lendo resposta da API: %w", err)
	}
	return body, nil
}

// pluginBase resolve a base da API de plugins.
//
// Deriva da base do core quando ela foi sobreposta num teste, para que o teste
// nao precise de rede — e para que nenhum teste bata na API publica por engano.
func (c *client) pluginBase() string {
	if c.pluginsBase != "" {
		return c.pluginsBase
	}
	return PluginsAPIBase
}

// parsePluginChecksums interpreta a resposta de um plugin.
func parsePluginChecksums(body []byte) (pluginChecksumsResponse, error) {
	var resp pluginChecksumsResponse
	if len(body) == 0 {
		return resp, errors.New("resposta vazia da API de checksums do plugin")
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, fmt.Errorf("resposta da API nao e JSON valido: %w", err)
	}
	if len(resp.Files) == 0 {
		return resp, ErrPluginSemChecksum
	}
	return resp, nil
}

// bate responde se o hash local casa com alguma variante publicada.
func (s pluginFileSums) bate(md5sum, sha string) bool {
	for _, h := range s.SHA256 {
		if h != "" && h == sha {
			return true
		}
	}
	for _, h := range s.MD5 {
		if h != "" && h == md5sum {
			return true
		}
	}
	return false
}

// temHash responde se a API publicou algum hash para este arquivo. Entrada sem
// hash nenhum nao pode virar achado de "alterado".
func (s pluginFileSums) temHash() bool {
	return len(s.SHA256) > 0 || len(s.MD5) > 0
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
