// Package amwscan integra o AMWScan (PHP Antimalware Scanner), um scanner em
// PHP puro que roda em qualquer hospedagem com PHP CLI.
//
// E o engine mais portatil do MVP: nao precisa de binario compilado, so de
// `php` na linha de comando — e das extensoes que ele usa, o que NAO e o
// mesmo que "so precisa de PHP" (ver Probe).
package amwscan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/config"
	sexec "github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Slug do engine.
const Slug = "amwscan"

// PharURL e de onde o executavel PHP do AMWScan e baixado.
//
// Aponta para dist/ no repositorio, e nao para o asset de um release: o
// projeto publica releases SEM asset (a v0.15.2 nao tem nenhum), e o
// .../releases/latest/download/scanner.phar responde 404. O dist/scanner do
// ramo principal e o unico caminho estavel.
const PharURL = "https://raw.githubusercontent.com/marcocesarato/PHP-Antimalware-Scanner/master/dist/scanner"

// MinPHPVersion exigida pelo engine.
const MinPHPVersion = "7.1"

// O escopo incremental do AMWScan é aplicado pelo ADAPTADOR, não pelo engine.
//
// Duas limitações reais, ambas medidas no container de validação, levam a essa
// escolha:
//
//  1. `--filter-paths` tem semântica de **E**, não de OU. Com um caminho ele
//     funciona; com dois ou mais o engine roda, sai com código 0, escreve o
//     relatório e não aponta NADA — nem os arquivos que casariam sozinhos.
//     Esse é o pior modo de falha possível para este projeto: engine verde,
//     relatório limpo, site infectado.
//  2. `--filter-paths` filtra o RELATÓRIO, não o conjunto varrido. Uma
//     execução por arquivo custou 1m37s para 11 arquivos, porque cada uma
//     varreu a raiz inteira de novo.
//
// Conclusão: uma execução por ciclo, sobre a raiz, e o Parse descarta o que o
// orquestrador não pediu. É mais CPU do que o ideal — o AMWScan simplesmente
// não sabe escanear uma lista de arquivos — mas é correto, e correto vem
// primeiro.

// chaveAlvos é onde o Scan guarda, no RawOutput, o conjunto de caminhos que o
// orquestrador pediu, para o Parse descartar o excedente.
const chaveAlvos = "alvos"

// FileStat sao os metadados que o orquestrador calcula sobre um arquivo
// apontado por um engine que nao reporta hash.
type FileStat struct {
	SHA256 string
	Size   int64
	Perms  string
	MTime  time.Time
}

// Adapter integra o AMWScan.
type Adapter struct {
	pharURL string
	http    *http.Client
	// stat e injetavel para que o teste de contrato exercite o parser com
	// fixtures que citam caminhos de um servidor real.
	stat func(string) (FileStat, bool)
}

// New cria o adaptador.
func New() *Adapter {
	return &Adapter{
		pharURL: PharURL,
		http:    &http.Client{Timeout: 2 * time.Minute},
		stat:    statFile,
	}
}

// WithStat troca a funcao de metadados. Uso restrito a testes.
func (a *Adapter) WithStat(fn func(string) (FileStat, bool)) *Adapter {
	a.stat = fn
	return a
}

func (a *Adapter) Info() adapter.Info {
	return adapter.Info{
		Slug:     Slug,
		Name:     "AMWScan (PHP Antimalware Scanner)",
		License:  "GPL-3.0 (invocado como processo externo, nunca linkado)",
		Homepage: "https://github.com/marcocesarato/PHP-Antimalware-Scanner",
		Kind:     schema.KindMalware,
		Categories: []schema.Category{
			schema.CategoryKnownMalware, schema.CategoryBackdoor, schema.CategoryWebshell,
			schema.CategoryObfuscation, schema.CategoryDropper, schema.CategoryInjection,
			schema.CategorySpamSEO, schema.CategoryPhishing, schema.CategoryOther,
		},
		Cost:          adapter.CostMedium,
		DefaultWeight: config.WeightAMWScan,
	}
}

// pharPath e onde o executavel fica instalado no espaco do usuario.
func pharPath(dataDir string) string {
	return filepath.Join(dataDir, "engines", "amwscan", "scanner.phar")
}

// reportBase e o prefixo do relatorio. O AMWScan acrescenta ".log".
func reportBase(dataDir string) string {
	return filepath.Join(dataDir, "engines", "amwscan", "relatorio")
}

var phpVersionRe = regexp.MustCompile(`PHP (\d+)\.(\d+)`)

// Probe checa PHP CLI, a presenca do executavel e — o que importa de verdade —
// se ele REALMENTE roda neste ambiente.
func (a *Adapter) Probe(ctx context.Context, env adapter.Environment) adapter.ProbeResult {
	php := env.BinaryPath
	if php == "" {
		php = "php"
	}
	if env.Runner == nil {
		return adapter.Unavailable("executor nao disponivel")
	}

	res := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-probe",
		Path:   php,
		Args:   []string{"-v"},
	})
	if res.Status != schema.StatusCompleted || res.ExitCode != 0 {
		return adapter.Unavailable(fmt.Sprintf(
			"PHP CLI nao encontrado ou nao executavel (%s): o AMWScan roda em PHP puro e sem ele nao ha como executar", php))
	}

	m := phpVersionRe.FindStringSubmatch(string(res.Stdout))
	if m == nil {
		return adapter.Unavailable("nao foi possivel identificar a versao do PHP CLI")
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	phpVer := fmt.Sprintf("%d.%d", major, minor)
	if major < 7 || (major == 7 && minor < 1) {
		return adapter.Unavailable(fmt.Sprintf(
			"PHP %s e mais antigo que o minimo exigido pelo AMWScan (%s)", phpVer, MinPHPVersion))
	}

	phar := pharPath(env.DataDir)
	info, err := os.Stat(phar)
	if err != nil {
		return adapter.UnavailableInstallable(fmt.Sprintf(
			"PHP %s disponivel, mas o AMWScan ainda nao foi instalado em %s", phpVer, phar))
	}

	// A checagem que realmente importa: EXECUTAR o engine.
	//
	// "PHP existe e o arquivo esta la" nao e o mesmo que "o engine roda". Numa
	// hospedagem sem a extensao mbstring, o AMWScan morre com exit 255 e
	// ZERO saida — e um probe que so olha versao e arquivo marcaria o engine
	// como saudavel enquanto ele nunca produz um achado. Isso e degradacao
	// silenciosa de cobertura, o modo de falha mais perigoso deste projeto.
	//
	// Este caso nao era hipotetico: foi assim que o container de validacao se
	// comportou antes de instalar php-mbstring.
	exec := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-selftest",
		Path:   php,
		Args:   []string{phar, "--version"},
	})
	saida := strings.TrimSpace(string(exec.Stdout)) + strings.TrimSpace(string(exec.Stderr))
	if exec.Status != schema.StatusCompleted || saida == "" {
		return adapter.Unavailable(fmt.Sprintf(
			"o AMWScan esta instalado mas nao executa neste PHP %s (saiu com codigo %d sem produzir saida). "+
				"A causa mais comum e falta de uma extensao do PHP, tipicamente mbstring: "+
				"peca `php-mbstring` ao suporte da hospedagem",
			phpVer, exec.ExitCode))
	}

	versao := "PHP " + phpVer
	if v := extrairVersao(saida); v != "" {
		versao = "AMWScan " + v + " (PHP " + phpVer + ")"
	}

	return adapter.ProbeResult{
		Available:           true,
		Version:             versao,
		BinaryPath:          phar,
		SignaturesUpdatedAt: info.ModTime(),
	}
}

var versaoRe = regexp.MustCompile(`(?i)version\s+v?(\d+\.\d+(?:\.\d+)?)`)

func extrairVersao(s string) string {
	if m := versaoRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// Install baixa o executavel para o espaco do usuario, sem root.
func (a *Adapter) Install(ctx context.Context, env adapter.Environment) error {
	if env.Offline {
		return errors.New("modo offline: nao e possivel baixar o AMWScan")
	}
	dest := pharPath(env.DataDir)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("criando diretorio do engine: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.pharURL, nil)
	if err != nil {
		return fmt.Errorf("montando download: %w", err)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("baixando o AMWScan: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download do AMWScan respondeu %s", resp.Status)
	}

	// Grava em temporario e renomeia: um download interrompido nao pode
	// deixar um executavel pela metade no lugar de um que funcionava.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".scanner-*.phar")
	if err != nil {
		return fmt.Errorf("criando arquivo temporario: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	n, err := io.Copy(tmp, io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gravando o AMWScan: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fechando o AMWScan: %w", err)
	}
	if n < 100<<10 {
		return fmt.Errorf("o download veio com apenas %d bytes: nao parece o scanner", n)
	}
	if err := os.Chmod(tmpName, 0o700); err != nil {
		return fmt.Errorf("ajustando permissao: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("instalando o AMWScan: %w", err)
	}
	return nil
}

// UpdateSignatures reinstala o executavel: no AMWScan as definicoes viajam
// dentro do proprio arquivo, entao atualizar assinatura e atualizar o engine.
func (a *Adapter) UpdateSignatures(ctx context.Context, env adapter.Environment) (time.Time, error) {
	if err := a.Install(ctx, env); err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(pharPath(env.DataDir))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Scan executa o AMWScan sobre a lista de caminhos.
//
// O AMWScan escreve o resultado num ARQUIVO de relatorio, nao em stdout — e
// nao tem formato JSON, so `html` e `txt`. A saida bruta deste adaptador e,
// portanto, o conteudo desse arquivo.
func (a *Adapter) Scan(ctx context.Context, env adapter.Environment, req adapter.ScanRequest) (adapter.RawOutput, error) {
	if env.Runner == nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, errors.New("executor nao disponivel")
	}
	php := env.BinaryPath
	if php == "" {
		php = "php"
	}
	phar := pharPath(env.DataDir)
	if _, err := os.Stat(phar); err != nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed},
			fmt.Errorf("AMWScan nao instalado em %s: %w", phar, err)
	}

	base := reportBase(env.DataDir)
	relatorio := base + ".log"

	out := adapter.RawOutput{
		Engine: Slug, ScanID: req.ScanID, Root: req.Root, Mode: req.Mode,
		StartedAt: time.Now(), PathsRequested: len(req.Paths),
		Status: schema.StatusCompleted,
		Extra:  map[string]any{},
	}
	// O Parse precisa saber o que foi realmente pedido para descartar o
	// excedente: o engine sempre varre a raiz inteira.
	if len(req.Paths) > 0 {
		out.Extra[chaveAlvos] = append([]string(nil), req.Paths...)
	}

	// Remove o relatorio anterior ANTES de rodar. Sem isso, uma execucao que
	// falha deixa o relatorio do ciclo passado no lugar, e o Parse devolveria
	// achados velhos como se fossem novos.
	if err := os.Remove(relatorio); err != nil && !os.IsNotExist(err) {
		out.Status = schema.StatusFailed
		return out, fmt.Errorf("limpando relatorio anterior: %w", err)
	}

	args := []string{
		"-d", "memory_limit=256M",
		phar,
		// --report: modo somente relatorio. Sem ele o AMWScan entra em modo
		// interativo e pode LIMPAR ou APAGAR arquivos — a quarentena deste
		// projeto e reversivel e registrada, a dele nao.
		"--report",
		"--report-format", "txt",
		"--path-report", base,
		"--no-colors",
		"--silent",
	}
	if req.MaxFileSizeBytes > 0 {
		args = append(args, "--max-filesize", strconv.FormatInt(req.MaxFileSizeBytes, 10))
	}
	args = append(args, env.ExtraArgs...)
	args = append(args, req.Root)

	res := env.Runner.Run(ctx, sexec.Command{
		Engine:  Slug,
		ScanID:  req.ScanID,
		Path:    php,
		Args:    args,
		Dir:     req.Root,
		Timeout: req.Timeout,
	})
	out.RawRef = res.RawRef
	out.FinishedAt = time.Now()

	if res.Abstains() {
		out.Status = res.Status
		return out, res.Err
	}

	// A saida bruta e o arquivo de relatorio. stdout fica vazio por causa do
	// --silent, e confundir "stdout vazio" com "nada achado" seria o erro
	// classico deste adaptador.
	conteudo, err := os.ReadFile(relatorio) // caminho derivado do diretorio de dados
	switch {
	case err == nil:
		out.Stdout = conteudo
	case os.IsNotExist(err):
		// Sem arquivo de relatorio nao ha o que interpretar. Se o engine
		// tivesse rodado, ele teria escrito ao menos o cabecalho.
		out.Status = schema.StatusFailed
		return out, fmt.Errorf(
			"o AMWScan terminou com codigo %d mas nao escreveu o relatorio em %s (saida: %q)",
			res.ExitCode, relatorio, primeiraLinha(res.Stderr))
	default:
		out.Status = schema.StatusFailed
		return out, fmt.Errorf("lendo relatorio do AMWScan: %w", err)
	}

	return out, nil
}

func primeiraLinha(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Formato real do relatorio txt do AMWScan 0.15.1:
//
//	Scan date: 2026-07-29 15:59:45
//	File: /caminho/do/arquivo.php
//	Exploits:
//	 => [!] Signature (d30fc49e) [line 4]
//	    - Malware Signature (hash: d30fc49e)
//	      => backdoor
//
// A hierarquia importa: `File:` abre um bloco, e tudo abaixo pertence a ele
// ate o proximo `File:`. Tratar as linhas isoladamente produziria achados sem
// arquivo.
var (
	arquivoRe = regexp.MustCompile(`^File:\s*(.+?)\s*$`)
	secaoRe   = regexp.MustCompile(`^([A-Za-z][A-Za-z ]*):\s*$`)
	achadoRe  = regexp.MustCompile(`^\s*=>\s*\[[!*]\]\s*(.+?)\s*(?:\(([^)]*)\))?\s*(?:\[line\s+(\d+)\])?\s*$`)
	tagRe     = regexp.MustCompile(`^\s+=>\s*(.+?)\s*$`)
	dataRe    = regexp.MustCompile(`^Scan date:\s*(.+?)\s*$`)
)

// Parse converte o relatorio txt do AMWScan para o esquema normalizado.
func (a *Adapter) Parse(raw adapter.RawOutput) (schema.ScanReport, error) {
	rep := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        raw.ScanID,
		Engine:        Slug,
		EngineVersion: raw.EngineVersion,
		StartedAt:     raw.StartedAt,
		FinishedAt:    raw.FinishedAt,
		Status:        schema.StatusCompleted,
		Scope: schema.Scope{
			Root: raw.Root, Mode: raw.Mode,
			FilesConsidered: raw.PathsRequested,
			FilesScanned:    raw.PathsRequested,
		},
		Findings: []schema.Finding{},
		RawRef:   raw.RawRef,
	}

	// Relatorio vazio e ambiguo demais para ser interpretado como "site
	// limpo": o AMWScan sempre escreve ao menos a linha `Scan date:`. Vazio
	// significa que ele nao chegou a escrever — abstencao.
	texto := strings.TrimSpace(string(raw.Stdout))
	if texto == "" {
		return rep, errors.New("o AMWScan nao produziu relatorio (arquivo vazio)")
	}
	if !strings.Contains(texto, "Scan date:") && !strings.Contains(texto, "File:") {
		return rep, fmt.Errorf("o relatorio do AMWScan nao tem o formato esperado (comeca com %q)",
			primeiraLinha([]byte(texto)))
	}

	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	// Quando o Scan varreu a raiz inteira (lote grande demais para uma
	// execucao por arquivo), o relatorio traz achados de arquivos que o
	// orquestrador NAO pediu. Descarta-los aqui e o que preserva o escopo
	// incremental: quem decide a lista e o orquestrador, sempre.
	permitido := alvosPermitidos(raw)

	type pendente struct {
		rule  string
		extra string
		linha int64
		tag   string
	}

	var (
		arquivoAtual  string
		atual         *pendente
		desconhecidas int
	)

	emitir := func() {
		if atual == nil || arquivoAtual == "" {
			atual = nil
			return
		}
		defer func() { atual = nil }()

		if permitido != nil && !permitido[arquivoAtual] {
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["fora_do_escopo_pedido"]++
			return
		}

		m, conhecida := classify(atual.rule, atual.tag)
		if !conhecida {
			desconhecidas++
		}
		st, ok := a.stat(arquivoAtual)
		if !ok || st.SHA256 == "" {
			// Sem hash nao ha como deduplicar entre engines. Pular e melhor
			// que inventar uma chave: o arquivo provavelmente sumiu entre o
			// scan e a leitura do relatorio.
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["sumiu_antes_do_hash"]++
			return
		}

		trecho := atual.rule
		if atual.extra != "" {
			trecho += " (" + atual.extra + ")"
		}
		if atual.tag != "" {
			trecho += " => " + atual.tag
		}

		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          atual.rule,
			RuleRef:       "https://github.com/marcocesarato/PHP-Antimalware-Scanner",
			File: schema.FileRef{
				Path:      arquivoAtual,
				SizeBytes: st.Size,
				SHA256:    st.SHA256,
				MTime:     st.MTime,
				Perms:     st.Perms,
			},
			Category:   m.category,
			Severity:   m.severity,
			Confidence: m.confidence,
			// O relatorio txt do AMWScan nao inclui o trecho do codigo, so a
			// regra e a linha. Melhor assim: conteudo malicioso nunca precisa
			// atravessar o sistema para o usuario entender o achado.
			MatchedContent: schema.SanitizeSnippet(trecho),
			MatchedOffset:  atual.linha,
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	sc := bufio.NewScanner(strings.NewReader(texto))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for sc.Scan() {
		linha := sc.Text()
		if strings.TrimSpace(linha) == "" {
			continue
		}

		if m := dataRe.FindStringSubmatch(linha); m != nil {
			continue
		}
		if m := arquivoRe.FindStringSubmatch(linha); m != nil {
			emitir()
			arquivoAtual = m[1]
			continue
		}
		if m := achadoRe.FindStringSubmatch(linha); m != nil {
			emitir()
			p := &pendente{rule: strings.TrimSpace(m[1]), extra: strings.TrimSpace(m[2])}
			if m[3] != "" {
				if n, err := strconv.ParseInt(m[3], 10, 64); err == nil {
					p.linha = n
				}
			}
			atual = p
			continue
		}
		// `Exploits:` / `Functions:` apenas separam secoes.
		if secaoRe.MatchString(linha) {
			continue
		}
		// A linha "      => backdoor" e a categoria que o engine atribuiu.
		if m := tagRe.FindStringSubmatch(linha); m != nil && atual != nil && atual.tag == "" {
			atual.tag = strings.TrimSpace(m[1])
			continue
		}
	}
	emitir()

	if err := sc.Err(); err != nil {
		return rep, fmt.Errorf("lendo relatorio do AMWScan: %w", err)
	}

	if desconhecidas > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["regra_desconhecida"] = desconhecidas
	}
	return rep, nil
}

// alvosPermitidos devolve o conjunto de caminhos que o orquestrador pediu, ou
// nil quando nao ha filtro a aplicar.
//
// nil e diferente de conjunto vazio: nil significa "aceite tudo o que o
// relatorio trouxer" (execucao por arquivo, ou reprocessamento de saida bruta
// arquivada, onde a lista original ja nao existe).
func alvosPermitidos(raw adapter.RawOutput) map[string]bool {
	if raw.Extra == nil {
		return nil
	}
	bruto, ok := raw.Extra[chaveAlvos]
	if !ok {
		return nil
	}
	lista, ok := bruto.([]string)
	if !ok || len(lista) == 0 {
		return nil
	}
	out := make(map[string]bool, len(lista))
	for _, p := range lista {
		out[p] = true
	}
	return out
}

// statFile le hash e metadados do arquivo apontado.
//
// O AMWScan nao reporta hash. Quem calcula e o orquestrador, porque o sha256 e
// a chave de deduplicacao entre engines e precisa ser calculado do mesmo jeito
// para todos — se cada adaptador usasse o hash do seu engine, dois engines
// apontando o mesmo arquivo virariam dois vereditos.
func statFile(path string) (FileStat, bool) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return FileStat{}, false
	}
	f, err := os.Open(path) // caminho vem do relatorio do engine sobre a raiz configurada
	if err != nil {
		return FileStat{}, false
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileStat{}, false
	}
	return FileStat{
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   info.Size(),
		Perms:  fmt.Sprintf("%04o", info.Mode().Perm()),
		MTime:  info.ModTime(),
	}, true
}
