package wpchecksums

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// scanPlugins verifica a integridade de cada plugin instalado.
//
// Nenhuma falha aqui derruba a verificação do core: um plugin que a API não
// conhece, ou uma requisição que falhou, entra em `pulados` com o motivo. O
// core é o sinal de maior peso do projeto e não pode ficar sem verificação
// porque um plugin de terceiro não tem checksum publicado.
func (a *Adapter) scanPlugins(ctx context.Context, root string) ([]pluginPayload, map[string]string) {
	pulados := map[string]string{}

	instalados, err := DetectPlugins(root)
	if err != nil {
		pulados["*"] = "nao foi possivel listar os plugins: " + err.Error()
		return nil, pulados
	}
	if len(instalados) == 0 {
		return nil, nil
	}

	if len(instalados) > maxPlugins {
		// Cortar em silêncio faria o relatório parecer completo. O usuário
		// precisa saber que 30 dos 70 plugins dele não foram olhados.
		for _, p := range instalados[maxPlugins:] {
			pulados[p.Slug] = fmt.Sprintf(
				"limite de %d plugins por ciclo atingido; sera verificado num proximo ciclo", maxPlugins)
		}
		instalados = instalados[:maxPlugins]
	}

	var out []pluginPayload
	for _, p := range instalados {
		if ctx.Err() != nil {
			pulados[p.Slug] = "ciclo cancelado antes de verificar este plugin"
			continue
		}
		if p.Version == "" {
			pulados[p.Slug] = "o plugin nao declara Version no cabecalho; sem versao nao ha checksum a consultar"
			continue
		}

		body, err := a.api.fetchPlugin(ctx, p.Slug, p.Version)
		if err != nil {
			if errors.Is(err, ErrPluginSemChecksum) {
				// Caso normal: plugin comercial, próprio, ou versão que saiu
				// do diretório oficial.
				pulados[p.Slug] = fmt.Sprintf(
					"a API nao publica checksums para %s %s (plugin comercial ou proprio?)", p.Slug, p.Version)
			} else {
				pulados[p.Slug] = "consulta a API falhou: " + err.Error()
			}
			continue
		}

		resp, err := parsePluginChecksums(body)
		if err != nil {
			pulados[p.Slug] = "resposta da API ilegivel: " + err.Error()
			continue
		}

		locais, ausentes := pluginInventory(p.Dir, resp.Files)

		// Mesma trava do core, calibrada para plugin: se falta muita coisa, o
		// diretório provavelmente não é a versão que o cabeçalho declara — e
		// emitir um achado por arquivo afogaria o relatório.
		if len(resp.Files) > 0 {
			fracao := float64(len(ausentes)) / float64(len(resp.Files))
			if fracao > maxMissingRatioPlugin {
				pulados[p.Slug] = fmt.Sprintf(
					"%d de %d arquivos de %s %s nao existem no disco (%.0f%%): "+
						"o diretorio provavelmente nao e a versao que o cabecalho declara",
					len(ausentes), len(resp.Files), p.Slug, p.Version, fracao*100)
				continue
			}
		}

		out = append(out, pluginPayload{
			Slug:        p.Slug,
			Name:        p.Name,
			Version:     p.Version,
			Dir:         p.Dir,
			APIResponse: body,
			Local:       locais,
			Missing:     ausentes,
			Extra:       extraPluginFiles(p.Dir, resp.Files, a.maxDepth),
		})
	}

	if len(pulados) == 0 {
		pulados = nil
	}
	return out, pulados
}

// parsePlugins transforma o payload de plugins em achados normalizados.
//
// Devolve também os sha256 que batem com o oficial: eles entram em
// `clean_files` junto com os do core, e viram veto no motor de veredito. Um
// arquivo legítimo de plugin apontado por heurística de outro engine precisa
// dessa mesma proteção — plugin costuma ter JS minificado e base64, que é
// exatamente o que gera falso positivo.
func (a *Adapter) parsePlugins(raw rawOutputInfo, payload rawPayload, detectedAt time.Time) ([]schema.Finding, []string) {
	var achados []schema.Finding
	var limpos []string

	for _, p := range payload.Plugins {
		resp, err := parsePluginChecksums(p.APIResponse)
		if err != nil {
			// O payload foi gravado com a resposta que já tinha sido validada;
			// chegar aqui significa arquivo bruto corrompido. Não inventa
			// achado a partir de dado que não dá para interpretar.
			continue
		}

		for rel, lf := range p.Local {
			oficial, ok := resp.Files[rel]
			if !ok || !oficial.temHash() {
				continue
			}
			if oficial.bate(lf.MD5, lf.SHA256) {
				limpos = append(limpos, lf.SHA256)
				continue
			}
			achados = append(achados, pluginFinding(raw, p, lf, detectedAt,
				"plugin_file_modified", schema.SeverityCritical, schema.ConfidenceSignature,
				fmt.Sprintf("arquivo alterado no plugin %s %s: %s", p.Slug, p.Version, rel)))
		}

		for _, rel := range p.Missing {
			lf := LocalFile{
				RelPath: rel,
				AbsPath: p.Dir + "/" + rel,
				SHA256:  pathHash(p.Dir + "/" + rel),
			}
			achados = append(achados, pluginFinding(raw, p, lf, detectedAt,
				"plugin_file_missing", schema.SeverityMedium, schema.ConfidenceAnomaly,
				fmt.Sprintf("arquivo oficial ausente no plugin %s %s: %s", p.Slug, p.Version, rel)))
		}

		for _, lf := range p.Extra {
			// Tolerância zero: plugin oficial não ganha `.php` por conta
			// própria. É o achado mais valioso deste verificador, porque um
			// backdoor dentro de um plugin legítimo não aparece na conferência
			// do core e o usuário nunca suspeita do que ele mesmo instalou.
			achados = append(achados, pluginFinding(raw, p, lf, detectedAt,
				"plugin_file_unexpected", schema.SeverityCritical, schema.ConfidenceSignature,
				fmt.Sprintf("arquivo executavel que nao pertence ao plugin %s %s: %s",
					p.Slug, p.Version, lf.RelPath)))
		}
	}

	sort.Strings(limpos)
	return achados, limpos
}

// rawOutputInfo e o mínimo que os construtores de Finding precisam do RawOutput.
type rawOutputInfo struct {
	ScanID        string
	EngineVersion string
}

func pluginFinding(
	raw rawOutputInfo,
	p pluginPayload,
	lf LocalFile,
	detectedAt time.Time,
	rule string,
	sev schema.Severity,
	conf schema.Confidence,
	msg string,
) schema.Finding {
	var mtime time.Time
	if lf.MTime > 0 {
		mtime = time.Unix(lf.MTime, 0)
	}
	return schema.Finding{
		SchemaVersion: schema.Version,
		Kind:          schema.KindMalware,
		Engine:        Slug,
		EngineVersion: raw.EngineVersion,
		Rule:          rule,
		RuleRef:       "https://downloads.wordpress.org/plugin-checksums/",
		File: schema.FileRef{
			Path:      lf.AbsPath,
			SizeBytes: lf.Size,
			SHA256:    lf.SHA256,
			MD5:       lf.MD5,
			MTime:     mtime,
			Perms:     lf.Perms,
		},
		Category:       schema.CategoryCoreIntegrity,
		Severity:       sev,
		Confidence:     conf,
		MatchedContent: schema.SanitizeSnippet(msg),
		ScanID:         raw.ScanID,
		DetectedAt:     detectedAt,
	}
}
