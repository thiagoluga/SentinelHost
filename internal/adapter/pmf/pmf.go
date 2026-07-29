// Package pmf integra o php-malware-finder, um conjunto de regras YARA para
// PHP malicioso.
//
// O engine e executado pelo binario `yara` externo, nunca por libyara: linkar
// a biblioteca exigiria CGO e quebraria o binario estatico exigido pelo
// Principio VII. Sem o `yara` no ambiente, o engine fica indisponivel com
// motivo claro e o consenso segue com os demais (plan.md, decisao tecnica 1).
package pmf

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
const Slug = "php-malware-finder"

// RulesURL e de onde as regras sao baixadas na instalacao.
const RulesURL = "https://raw.githubusercontent.com/jvoisin/php-malware-finder/master/php-malware-finder/php.yar"

// FileStat sao os metadados calculados pelo orquestrador.
type FileStat struct {
	SHA256 string
	Size   int64
	Perms  string
	MTime  time.Time
}

// Adapter integra o php-malware-finder via binario yara.
type Adapter struct {
	rulesURL string
	stat     func(string) (FileStat, bool)
	// download e injetavel nos testes.
	download func(ctx context.Context, url, dest string) error
}

// New cria o adaptador.
func New() *Adapter {
	return &Adapter{rulesURL: RulesURL, stat: statFile, download: downloadFile}
}

// WithStat troca a funcao de metadados. Uso restrito a testes.
func (a *Adapter) WithStat(fn func(string) (FileStat, bool)) *Adapter {
	a.stat = fn
	return a
}

func (a *Adapter) Info() adapter.Info {
	return adapter.Info{
		Slug:     Slug,
		Name:     "php-malware-finder (regras YARA)",
		License:  "GPL-3.0 (regras e binario yara usados como processo externo, nunca linkados)",
		Homepage: "https://github.com/jvoisin/php-malware-finder",
		Kind:     schema.KindMalware,
		Categories: []schema.Category{
			schema.CategoryObfuscation, schema.CategoryBackdoor, schema.CategoryWebshell,
			schema.CategorySpamSEO, schema.CategoryPhishing, schema.CategoryInjection,
			schema.CategoryDropper, schema.CategorySuspiciousLocation,
			schema.CategorySuspiciousPerms, schema.CategoryKnownMalware, schema.CategoryOther,
		},
		Cost:          adapter.CostMedium,
		DefaultWeight: config.WeightPMF,
	}
}

func rulesPath(dataDir string) string {
	return filepath.Join(dataDir, "engines", "pmf", "php.yar")
}

var yaraVersionRe = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)

// Probe checa o binario yara e as regras.
func (a *Adapter) Probe(ctx context.Context, env adapter.Environment) adapter.ProbeResult {
	if env.Runner == nil {
		return adapter.Unavailable("executor nao disponivel")
	}
	yara := env.BinaryPath
	if yara == "" {
		yara = "yara"
	}

	res := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-probe",
		Path:   yara,
		Args:   []string{"--version"},
	})
	if res.Status != schema.StatusCompleted || res.ExitCode != 0 {
		return adapter.Unavailable(
			"binario `yara` nao encontrado no PATH. O php-malware-finder e um conjunto de regras YARA e precisa do yara para rodar; " +
				"sem ele este engine se abstem e o consenso segue com os demais")
	}
	versao := "desconhecida"
	if m := yaraVersionRe.FindStringSubmatch(string(res.Stdout)); m != nil {
		versao = m[1]
	}

	rules := rulesPath(env.DataDir)
	info, err := os.Stat(rules)
	if err != nil {
		return adapter.UnavailableInstallable(fmt.Sprintf(
			"yara %s disponivel, mas as regras do php-malware-finder ainda nao foram instaladas em %s", versao, rules))
	}

	return adapter.ProbeResult{
		Available:           true,
		Version:             "yara " + versao,
		BinaryPath:          rules,
		SignaturesUpdatedAt: info.ModTime(),
	}
}

// Install baixa as regras para o espaco do usuario.
func (a *Adapter) Install(ctx context.Context, env adapter.Environment) error {
	if env.Offline {
		return errors.New("modo offline: nao e possivel baixar as regras YARA")
	}
	dest := rulesPath(env.DataDir)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("criando diretorio das regras: %w", err)
	}
	return a.download(ctx, a.rulesURL, dest)
}

// UpdateSignatures rebaixa as regras.
func (a *Adapter) UpdateSignatures(ctx context.Context, env adapter.Environment) (time.Time, error) {
	if err := a.Install(ctx, env); err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(rulesPath(env.DataDir))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Scan roda o yara sobre a lista de caminhos.
func (a *Adapter) Scan(ctx context.Context, env adapter.Environment, req adapter.ScanRequest) (adapter.RawOutput, error) {
	if env.Runner == nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, errors.New("executor nao disponivel")
	}
	yara := env.BinaryPath
	if yara == "" {
		yara = "yara"
	}
	rules := rulesPath(env.DataDir)
	if _, err := os.Stat(rules); err != nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed},
			fmt.Errorf("regras YARA nao instaladas em %s: %w", rules, err)
	}

	args := []string{
		"--no-warnings",
		"-s", // imprime as strings casadas, que viram matched_content
		"-w",
		// Um arquivo ofuscado pode casar milhares de vezes na mesma regra.
		// Sem teto, a saida de UM arquivo domina o relatorio inteiro — e o
		// matched_content e truncado a 512 bytes de qualquer jeito.
		"--max-strings-per-rule", "20",
	}
	// O limite de tamanho de arquivo e aplicado pelo walker do orquestrador,
	// nao aqui: quem decide o escopo e o orquestrador (contrato de adaptadores).
	args = append(args, env.ExtraArgs...)
	args = append(args, rules)
	// yara aceita "@arquivo" com a lista de alvos.
	listFile, cleanup, err := writeTargetList(env.DataDir, req)
	if err != nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, err
	}
	defer cleanup()
	args = append(args, "@"+listFile)

	res := env.Runner.Run(ctx, sexec.Command{
		Engine:  Slug,
		ScanID:  req.ScanID,
		Path:    yara,
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

func writeTargetList(dataDir string, req adapter.ScanRequest) (string, func(), error) {
	dir := filepath.Join(dataDir, "engines", "pmf")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", func() {}, fmt.Errorf("criando diretorio de trabalho: %w", err)
	}
	f, err := os.CreateTemp(dir, "alvos-*.txt")
	if err != nil {
		return "", func() {}, fmt.Errorf("criando lista de alvos: %w", err)
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := f.WriteString(strings.Join(req.Paths, "\n") + "\n"); err != nil {
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

// stringLineRe casa as linhas de string do yara -s: "0x1f2:$nome: trecho".
// Grupos: offset em hexadecimal, nome da string, trecho casado.
var stringLineRe = regexp.MustCompile(`^0x([0-9a-fA-F]+):\$?([^:]*):\s?(.*)$`)

// Parse converte a saida de texto do yara para o esquema normalizado.
//
// O formato tem hierarquia: uma linha "REGRA CAMINHO" sem indentacao, seguida
// das linhas de string que pertencem a ela. Tratar cada linha isoladamente
// produziria achados sem arquivo.
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

	// Saida vazia com processo COMPLETO significa "nenhuma regra bateu" — o
	// caminho normal e feliz. Saida vazia com processo que falhou ja foi
	// convertida em abstencao antes de chegar aqui, pelo SafeScanAndParse.
	// Por isso este Parse nao pode inventar erro para stdout vazio: seria
	// transformar um site limpo em falha de engine.
	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	type pendente struct {
		rule    string
		path    string
		strings []string
		// offset da primeira string casada, para que o usuario saiba onde
		// olhar no arquivo.
		offset int64
	}
	var atual *pendente
	desconhecidas := 0

	flush := func() {
		if atual == nil {
			return
		}
		defer func() { atual = nil }()

		m, conhecida := classify(atual.rule)
		if !conhecida {
			desconhecidas++
		}
		st, ok := a.stat(atual.path)
		if !ok || st.SHA256 == "" {
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["sumiu_antes_do_hash"]++
			return
		}
		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          atual.rule,
			RuleRef:       "https://github.com/jvoisin/php-malware-finder",
			File: schema.FileRef{
				Path:      atual.path,
				SizeBytes: st.Size,
				SHA256:    st.SHA256,
				MTime:     st.MTime,
				Perms:     st.Perms,
			},
			Category:   m.category,
			Severity:   m.severity,
			Confidence: m.confidence,
			// O trecho casado e truncado e sanitizado: conteudo malicioso
			// nunca e re-servido pela UI.
			MatchedContent: schema.SanitizeSnippet(strings.Join(atual.strings, " | ")),
			MatchedOffset:  atual.offset,
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	sc := bufio.NewScanner(strings.NewReader(string(raw.Stdout)))
	// Linhas de yara -s podem ser longas; o default de 64 KiB nao basta.
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for sc.Scan() {
		linha := sc.Text()
		if strings.TrimSpace(linha) == "" {
			continue
		}
		if m := stringLineRe.FindStringSubmatch(linha); m != nil {
			if atual != nil {
				if len(atual.strings) == 0 {
					if off, err := strconv.ParseInt(m[1], 16, 64); err == nil {
						atual.offset = off
					}
				}
				atual.strings = append(atual.strings, m[3])
			}
			// String sem regra anterior e lixo de saida truncada; ignorar e
			// melhor que criar um achado sem arquivo.
			continue
		}

		rule, path, ok := strings.Cut(linha, " ")
		if !ok || rule == "" || path == "" {
			continue
		}
		flush()
		atual = &pendente{rule: rule, path: strings.TrimSpace(path)}
	}
	flush()

	if err := sc.Err(); err != nil {
		return rep, fmt.Errorf("lendo saida do yara: %w", err)
	}

	if desconhecidas > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["regra_desconhecida"] = desconhecidas
	}
	return rep, nil
}

func statFile(path string) (FileStat, bool) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return FileStat{}, false
	}
	f, err := os.Open(path) //nolint:gosec // caminho vem da saida do engine sobre a raiz configurada
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
