// Package amwscan integra o AMWScan (PHP Antimalware Scanner), um scanner em
// PHP puro que roda em qualquer hospedagem com PHP CLI.
//
// E o engine mais portatil do MVP: nao precisa de binario compilado, so de
// `php` na linha de comando.
package amwscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// PharURL e de onde o phar e baixado quando o usuario pede a instalacao.
const PharURL = "https://github.com/marcocesarato/PHP-Antimalware-Scanner/releases/latest/download/scanner.phar"

// MinPHPVersion exigida pelo engine.
const MinPHPVersion = "7.1"

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
	// pharURL e sobreponivel nos testes.
	pharURL string
	http    *http.Client
	// stat e injetavel para que o teste de contrato possa exercitar o parser
	// com fixtures que citam caminhos de um servidor real, sem precisar
	// materializar essa arvore no disco da maquina de teste.
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

// pharPath e onde o phar fica instalado no espaco do usuario.
func pharPath(dataDir string) string {
	return filepath.Join(dataDir, "engines", "amwscan", "scanner.phar")
}

var phpVersionRe = regexp.MustCompile(`PHP (\d+)\.(\d+)`)

// Probe checa PHP CLI e a presenca do phar.
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
			"PHP %s disponivel, mas o scanner.phar ainda nao foi instalado em %s", phpVer, phar))
	}

	return adapter.ProbeResult{
		Available:           true,
		Version:             "PHP " + phpVer,
		BinaryPath:          phar,
		SignaturesUpdatedAt: info.ModTime(),
	}
}

// Install baixa o phar para o espaco do usuario, sem root.
func (a *Adapter) Install(ctx context.Context, env adapter.Environment) error {
	if env.Offline {
		return errors.New("modo offline: nao e possivel baixar o scanner.phar")
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
		return fmt.Errorf("baixando scanner.phar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download do scanner.phar respondeu %s", resp.Status)
	}

	// Grava em temporario e renomeia: um download interrompido nao pode
	// deixar um phar pela metade no lugar de um que funcionava.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".scanner-*.phar")
	if err != nil {
		return fmt.Errorf("criando arquivo temporario: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 64<<20)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gravando scanner.phar: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fechando scanner.phar: %w", err)
	}
	if err := os.Chmod(tmpName, 0o700); err != nil {
		return fmt.Errorf("ajustando permissao do scanner.phar: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("instalando scanner.phar: %w", err)
	}
	return nil
}

// UpdateSignatures reinstala o phar: no AMWScan as assinaturas viajam dentro
// do proprio arquivo, entao atualizar assinatura e atualizar o engine.
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

// Scan executa o phar sobre a lista de caminhos.
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
			fmt.Errorf("scanner.phar nao instalado em %s: %w", phar, err)
	}

	// Lista de alvos por arquivo, para respeitar o escopo incremental decidido
	// pelo orquestrador. Passar so a raiz faria o engine varrer tudo de novo e
	// jogar fora o trabalho do baseline.
	listFile, cleanup, err := writeTargetList(env.DataDir, req)
	if err != nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, err
	}
	defer cleanup()

	args := []string{
		"-d", "memory_limit=256M",
		phar,
		"--report",
		"--format", "json",
		"--filter-paths-list", listFile,
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

	out := adapter.FromExecResult(req, Slug, res)
	if res.Abstains() {
		return out, res.Err
	}
	return out, nil
}

// writeTargetList grava a lista de arquivos a escanear.
func writeTargetList(dataDir string, req adapter.ScanRequest) (string, func(), error) {
	dir := filepath.Join(dataDir, "engines", "amwscan")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", func() {}, fmt.Errorf("criando diretorio de trabalho: %w", err)
	}
	f, err := os.CreateTemp(dir, "alvos-*.txt")
	if err != nil {
		return "", func() {}, fmt.Errorf("criando lista de alvos: %w", err)
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }

	if _, err := f.WriteString(strings.Join(req.Paths, "\n")); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("gravando lista de alvos: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("fechando lista de alvos: %w", err)
	}
	return name, cleanup, nil
}

// report e o JSON que o AMWScan emite com --report --format json.
type report struct {
	Version  string      `json:"version"`
	Path     string      `json:"path"`
	Scanned  int         `json:"scanned"`
	Detected int         `json:"detected"`
	Time     float64     `json:"time"`
	Logs     []reportLog `json:"logs"`
}

type reportLog struct {
	File    string `json:"file"`
	Exploit string `json:"exploit"`
	Line    int    `json:"line"`
	Details string `json:"details"`
	Match   string `json:"match"`
	Size    int64  `json:"size"`
}

// Parse converte o JSON do AMWScan para o esquema normalizado.
func (a *Adapter) Parse(raw adapter.RawOutput) (schema.ScanReport, error) {
	rep := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        raw.ScanID,
		Engine:        Slug,
		StartedAt:     raw.StartedAt,
		FinishedAt:    raw.FinishedAt,
		Status:        schema.StatusCompleted,
		Scope:         schema.Scope{Root: raw.Root, Mode: raw.Mode},
		Findings:      []schema.Finding{},
		RawRef:        raw.RawRef,
	}

	// Saida vazia com processo bem-sucedido nao acontece no AMWScan: ele
	// sempre emite o JSON do relatorio. Vazio aqui significa que o engine
	// morreu antes de escrever — abstencao, nunca "nao achou nada".
	trimmed := strings.TrimSpace(string(raw.Stdout))
	if trimmed == "" {
		return rep, errors.New("o AMWScan nao produziu relatorio (saida vazia)")
	}

	var r report
	if err := json.Unmarshal([]byte(trimmed), &r); err != nil {
		return rep, fmt.Errorf("relatorio do AMWScan ilegivel: %w", err)
	}

	rep.EngineVersion = r.Version
	rep.Scope.FilesScanned = r.Scanned
	rep.Scope.FilesConsidered = raw.PathsRequested
	rep.ResourceUsage.WallSeconds = r.Time

	// Divergencia entre o contador e a lista significa relatorio truncado. Um
	// relatorio parcial aceito como bom esconderia achados reais.
	if r.Detected != len(r.Logs) {
		return rep, fmt.Errorf(
			"relatorio truncado: o AMWScan declara %d deteccoes mas listou %d", r.Detected, len(r.Logs))
	}

	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	desconhecidas := 0
	for _, l := range r.Logs {
		if l.File == "" {
			// Achado sem arquivo nao tem alvo no consenso; contabiliza como
			// anomalia do engine em vez de virar um veredito fantasma.
			desconhecidas++
			continue
		}
		m, conhecida := classify(l.Exploit)
		if !conhecida {
			desconhecidas++
		}

		st, ok := a.stat(l.File)
		if !ok || st.SHA256 == "" {
			// Sem hash nao ha como deduplicar entre engines. Pular e melhor
			// que inventar uma chave: o arquivo provavelmente ja foi removido
			// entre o scan e a leitura do relatorio.
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["sumiu_antes_do_hash"]++
			continue
		}
		size := st.Size
		if l.Size > 0 {
			size = l.Size
		}

		rule := l.Exploit
		if rule == "" {
			rule = "REGRA_NAO_INFORMADA"
		}
		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: r.Version,
			Rule:          rule,
			RuleRef:       "https://github.com/marcocesarato/PHP-Antimalware-Scanner",
			File: schema.FileRef{
				Path:      l.File,
				SizeBytes: size,
				SHA256:    st.SHA256,
				MTime:     st.MTime,
				Perms:     st.Perms,
			},
			Category:       m.category,
			Severity:       m.severity,
			Confidence:     m.confidence,
			MatchedContent: schema.SanitizeSnippet(snippet(l)),
			MatchedOffset:  int64(l.Line),
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	if desconhecidas > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["regra_desconhecida"] = desconhecidas
	}
	return rep, nil
}

func snippet(l reportLog) string {
	if l.Match != "" {
		return l.Match
	}
	return l.Details
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
	f, err := os.Open(path) //nolint:gosec // caminho vem do relatorio do engine sobre a raiz configurada
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
