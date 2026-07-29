package schema

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrIncompatibleVersion indica objeto de uma versao de esquema que este
// binario nao sabe ler.
var ErrIncompatibleVersion = errors.New("versao de esquema incompativel")

// ValidationError agrega todos os problemas de um objeto de uma vez. Um
// adaptador quebrado deve ver a lista inteira do que precisa corrigir, nao um
// erro por execucao.
type ValidationError struct {
	Object   string
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s invalido: %s", e.Object, strings.Join(e.Problems, "; "))
}

type problems struct {
	list []string
}

func (p *problems) addf(format string, args ...any) {
	p.list = append(p.list, fmt.Sprintf(format, args...))
}

func (p *problems) result(object string) error {
	if len(p.list) == 0 {
		return nil
	}
	return &ValidationError{Object: object, Problems: p.list}
}

// CompatibleVersion aceita objetos da mesma versao maior do esquema.
//
// Vazio e aceito e tratado como Version: adaptadores de terceiros escritos
// antes do campo existir continuam funcionando. Uma versao maior que a nossa e
// recusada — ler um esquema do futuro adivinhando campos e como um adaptador
// mente para o motor de veredito.
func CompatibleVersion(v string) error {
	if v == "" || v == Version {
		return nil
	}
	got, err := majorOf(v)
	if err != nil {
		return fmt.Errorf("%w: %q nao e semver", ErrIncompatibleVersion, v)
	}
	mine, err := majorOf(Version)
	if err != nil {
		return fmt.Errorf("%w: versao interna %q invalida", ErrIncompatibleVersion, Version)
	}
	if got != mine {
		return fmt.Errorf("%w: objeto e %q, este binario le %q", ErrIncompatibleVersion, v, Version)
	}
	return nil
}

func majorOf(v string) (int, error) {
	part, _, _ := strings.Cut(v, ".")
	return strconv.Atoi(part)
}

// isSHA256 valida o formato do hash. O motor de veredito deduplica por este
// campo; um hash malformado silenciosamente criaria um alvo separado e
// dividiria os votos de um mesmo arquivo entre dois vereditos.
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// Validate checa um Finding vindo de um adaptador.
func (f Finding) Validate() error {
	var p problems

	if err := CompatibleVersion(f.SchemaVersion); err != nil {
		p.addf("%v", err)
	}
	if f.Engine == "" {
		p.addf("engine vazio")
	}
	if f.Rule == "" {
		p.addf("rule vazia (use o nome que o engine reporta)")
	}
	if k := f.EffectiveKind(); !k.Valid() {
		p.addf("kind %q desconhecido", f.Kind)
	}
	if !f.Category.Valid() {
		p.addf("category %q desconhecida (mapeie para other se nao souber)", f.Category)
	}
	if !f.Severity.Valid() {
		p.addf("severity %q desconhecida", f.Severity)
	}
	if !f.Confidence.Valid() {
		p.addf("confidence %q desconhecida", f.Confidence)
	}
	if f.DetectedAt.IsZero() {
		p.addf("detected_at zerado")
	}
	if len(f.MatchedContent) > MaxMatchedContentBytes {
		p.addf("matched_content tem %d bytes, limite e %d (use SanitizeSnippet)",
			len(f.MatchedContent), MaxMatchedContentBytes)
	}

	switch f.EffectiveKind() {
	case KindVulnerability:
		// Vulnerabilidade e consolidada por componente, nao por arquivo:
		// sha256 nao e obrigatorio, component e.
		if f.Component == nil {
			p.addf("kind=vulnerability exige o bloco component")
		} else {
			if f.Component.Slug == "" {
				p.addf("component.slug vazio")
			}
			if f.Component.InstalledVersion == "" {
				p.addf("component.installed_version vazio")
			}
		}
	default:
		if !isSHA256(f.File.SHA256) {
			p.addf("file.sha256 %q invalido: e a chave de deduplicacao entre engines, e obrigatorio", f.File.SHA256)
		}
		if f.File.Path == "" {
			p.addf("file.path vazio")
		}
	}

	return p.result("Finding")
}

// Validate checa um ScanReport produzido por um adaptador.
func (r ScanReport) Validate() error {
	var p problems

	if err := CompatibleVersion(r.SchemaVersion); err != nil {
		p.addf("%v", err)
	}
	if r.ScanID == "" {
		p.addf("scan_id vazio")
	}
	if r.Engine == "" {
		p.addf("engine vazio")
	}
	if !r.Status.Valid() {
		p.addf("status %q desconhecido", r.Status)
	}
	// Um status de falha sem motivo transforma um problema diagnosticavel em
	// mistério para o usuario.
	if r.Status.Valid() && !r.Status.CountsAsVote() && r.Error == "" {
		p.addf("status %q exige error preenchido", r.Status)
	}
	if r.Scope.Mode != "" && !r.Scope.Mode.Valid() {
		p.addf("scope.mode %q desconhecido", r.Scope.Mode)
	}
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		p.addf("finished_at anterior a started_at")
	}

	for i, f := range r.Findings {
		if err := f.Validate(); err != nil {
			p.addf("findings[%d]: %v", i, err)
		}
		if f.Engine != "" && r.Engine != "" && f.Engine != r.Engine {
			p.addf("findings[%d]: engine %q difere do relatorio (%q)", i, f.Engine, r.Engine)
		}
	}
	for i, h := range r.CleanFiles {
		if !isSHA256(h) {
			p.addf("clean_files[%d]: sha256 %q invalido", i, h)
		}
	}

	return p.result("ScanReport")
}

// Validate checa um Verdict antes de ser persistido ou exibido.
func (v Verdict) Validate() error {
	var p problems

	if err := CompatibleVersion(v.SchemaVersion); err != nil {
		p.addf("%v", err)
	}
	if v.VerdictID == "" {
		p.addf("verdict_id vazio")
	}
	if !isSHA256(v.FileSHA256) {
		p.addf("file_sha256 %q invalido", v.FileSHA256)
	}
	if !v.Level.Valid() {
		p.addf("level %q desconhecido", v.Level)
	}
	if v.Score < 0 || v.Score > 1 {
		p.addf("score %v fora de [0,1]", v.Score)
	}
	if v.ActionTaken != "" && !v.ActionTaken.Valid() {
		p.addf("action_taken %q desconhecido", v.ActionTaken)
	}
	if v.ActionTaken == ActionQuarantined && v.QuarantineRef == "" {
		p.addf("action_taken=quarantined exige quarantine_ref (sem ele o arquivo nao e restauravel)")
	}
	if v.ActionTaken == ActionFailed && v.ActionError == "" {
		p.addf("action_taken=failed exige action_error")
	}
	for i, vote := range v.Votes {
		if vote.Engine == "" {
			p.addf("votes[%d]: engine vazio", i)
		}
		if vote.Weight < 0 {
			p.addf("votes[%d]: weight negativo", i)
		}
	}

	return p.result("Verdict")
}
