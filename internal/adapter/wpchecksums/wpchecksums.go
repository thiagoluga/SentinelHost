package wpchecksums

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Adapter e o adaptador nativo de integridade do WordPress.
type Adapter struct {
	api *client
	// maxDepth limita a busca por arquivos extras.
	maxDepth int
}

// New cria o adaptador com a API oficial.
func New() *Adapter { return &Adapter{api: newClient(""), maxDepth: 12} }

// NewWithBase cria o adaptador apontando para outra base de API (testes).
func NewWithBase(base string) *Adapter { return &Adapter{api: newClient(base), maxDepth: 12} }

func (a *Adapter) Info() adapter.Info {
	return adapter.Info{
		Slug:     Slug,
		Name:     "Integridade do core WordPress",
		License:  "N/A (nativo; consulta a API publica do WordPress.org)",
		Homepage: "https://codex.wordpress.org/WordPress.org_API",
		Kind:     schema.KindMalware,
		Categories: []schema.Category{
			schema.CategoryCoreIntegrity,
			schema.CategorySuspiciousLocation,
		},
		Cost:            adapter.CostLight,
		RequiresNetwork: true,
		DefaultWeight:   config.WeightWPChecksums,
	}
}

// Probe verifica se ha WordPress na raiz.
//
// A raiz vem em env.BinaryPath por convencao deste adaptador nativo: ele nao
// tem binario, e o que ele precisa saber e onde procurar.
func (a *Adapter) Probe(_ context.Context, env adapter.Environment) adapter.ProbeResult {
	root := env.BinaryPath
	if root == "" {
		return adapter.Unavailable("raiz do site nao informada ao adaptador")
	}
	inst, err := Detect(root)
	if err != nil {
		// Nao e falha: e um site que nao e WordPress. O adaptador se abstem
		// sem penalizar os demais engines.
		return adapter.Unavailable(err.Error())
	}
	if env.Offline {
		return adapter.Unavailable(fmt.Sprintf(
			"WordPress %s detectado, mas o modo offline impede consultar os checksums oficiais", inst.Version))
	}
	return adapter.ProbeResult{
		Available:  true,
		Version:    "WordPress " + inst.Version,
		BinaryPath: root,
	}
}

// Install nao se aplica: o adaptador e nativo.
func (a *Adapter) Install(context.Context, adapter.Environment) error {
	return adapter.ErrNotInstallable
}

// UpdateSignatures nao se aplica: os checksums sao buscados a cada scan e
// refletem sempre a versao instalada naquele momento.
func (a *Adapter) UpdateSignatures(context.Context, adapter.Environment) (time.Time, error) {
	return time.Time{}, nil
}

// rawPayload e o que este adaptador arquiva como saida bruta.
//
// A resposta da API vai crua em APIResponse; o inventario local vai junto para
// que o Parse consiga trabalhar sem reler o disco. Ao contrario dos outros
// engines, reprocessar um scan antigo daqui tem valor limitado: integridade e
// uma pergunta sobre o estado ATUAL dos arquivos.
type rawPayload struct {
	WPVersion   string               `json:"wp_version"`
	Root        string               `json:"root"`
	APIResponse json.RawMessage      `json:"api_response"`
	Local       map[string]LocalFile `json:"local"`
	Missing     []string             `json:"missing"`
	Extra       []LocalFile          `json:"extra"`
	FetchedAt   time.Time            `json:"fetched_at"`
}

// Scan consulta a API e monta o inventario local.
func (a *Adapter) Scan(ctx context.Context, env adapter.Environment, req adapter.ScanRequest) (adapter.RawOutput, error) {
	started := time.Now()
	out := adapter.RawOutput{
		Engine:         Slug,
		ScanID:         req.ScanID,
		Root:           req.Root,
		Mode:           req.Mode,
		StartedAt:      started,
		PathsRequested: len(req.Paths),
	}

	inst, err := Detect(req.Root)
	if err != nil {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, err
	}
	out.EngineVersion = "WordPress " + inst.Version

	if env.Offline {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, fmt.Errorf("modo offline: sem consulta a API de checksums")
	}

	body, err := a.api.fetch(ctx, inst.Version, inst.Locale)
	if err != nil {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		// Sem rede o adaptador se abstem. Declarar o core limpo por nao ter
		// conseguido perguntar seria o pior erro possivel deste engine.
		return out, fmt.Errorf("sem checksums oficiais: %w", err)
	}

	sums, err := parseChecksums(body)
	if err != nil {
		out.Stdout = body
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, err
	}

	local, missing := inventory(req.Root, sums)
	payload := rawPayload{
		WPVersion:   inst.Version,
		Root:        req.Root,
		APIResponse: body,
		Local:       local,
		Missing:     missing,
		Extra:       extraFiles(req.Root, sums, a.maxDepth),
		FetchedAt:   time.Now(),
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, fmt.Errorf("serializando inventario: %w", err)
	}

	out.Stdout = blob
	out.Status = schema.StatusCompleted
	out.FinishedAt = time.Now()
	return out, nil
}

// Parse compara o inventario com os checksums oficiais.
func (a *Adapter) Parse(raw adapter.RawOutput) (schema.ScanReport, error) {
	rep := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        raw.ScanID,
		Engine:        Slug,
		EngineVersion: raw.EngineVersion,
		StartedAt:     raw.StartedAt,
		FinishedAt:    raw.FinishedAt,
		Status:        schema.StatusCompleted,
		Scope:         schema.Scope{Root: raw.Root, Mode: raw.Mode},
		Findings:      []schema.Finding{},
		RawRef:        raw.RawRef,
	}

	var payload rawPayload
	if err := json.Unmarshal(raw.Stdout, &payload); err != nil {
		return rep, fmt.Errorf("inventario ilegivel: %w", err)
	}
	sums, err := parseChecksums(payload.APIResponse)
	if err != nil {
		return rep, err
	}

	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	// Arquivos que BATEM viram clean_files: o voto positivo de legitimidade.
	clean := make([]string, 0, len(payload.Local))
	for rel, lf := range payload.Local {
		oficial, ok := sums[rel]
		if !ok {
			continue
		}
		if lf.MD5 == oficial {
			clean = append(clean, lf.SHA256)
			continue
		}
		rep.Findings = append(rep.Findings, finding(
			raw, lf, detectedAt,
			"core_file_modified",
			fmt.Sprintf("arquivo do core alterado: %s", rel),
		))
	}
	rep.CleanFiles = clean

	// Arquivo do core ausente: alguem apagou ou substituiu parte da instalacao.
	for _, rel := range payload.Missing {
		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          "core_file_missing",
			RuleRef:       "https://codex.wordpress.org/WordPress.org_API",
			File: schema.FileRef{
				Path: payload.Root + "/" + rel,
				// Arquivo ausente nao tem hash. O motor de veredito deduplica
				// por sha256, entao usamos o hash do CAMINHO para que o achado
				// tenha uma chave estavel entre ciclos sem fingir ser um
				// arquivo que existe.
				SHA256: pathHash(payload.Root + "/" + rel),
			},
			Category:       schema.CategoryCoreIntegrity,
			Severity:       schema.SeverityHigh,
			Confidence:     schema.ConfidenceSignature,
			MatchedContent: schema.SanitizeSnippet("arquivo oficial do core ausente: " + rel),
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	// Arquivo executavel a mais dentro de wp-admin/ ou wp-includes/.
	for _, lf := range payload.Extra {
		rep.Findings = append(rep.Findings, finding(
			raw, lf, detectedAt,
			"core_file_unexpected",
			fmt.Sprintf("arquivo executavel que nao pertence ao core: %s", lf.RelPath),
		))
	}

	rep.Scope.FilesConsidered = len(sums)
	rep.Scope.FilesScanned = len(payload.Local) + len(payload.Extra)
	return rep, nil
}

func finding(raw adapter.RawOutput, lf LocalFile, detectedAt time.Time, rule, msg string) schema.Finding {
	return schema.Finding{
		SchemaVersion: schema.Version,
		Kind:          schema.KindMalware,
		Engine:        Slug,
		EngineVersion: raw.EngineVersion,
		Rule:          rule,
		RuleRef:       "https://codex.wordpress.org/WordPress.org_API",
		File: schema.FileRef{
			Path:      lf.AbsPath,
			SizeBytes: lf.Size,
			SHA256:    lf.SHA256,
			MD5:       lf.MD5,
			MTime:     time.Unix(lf.MTime, 0),
			Perms:     lf.Perms,
		},
		Category: schema.CategoryCoreIntegrity,
		// Divergencia de checksum oficial e prova, nao suspeita: o arquivo
		// nao e o que o WordPress.org publicou. Por isso confidence=signature
		// e severity=critical — e o que sustenta o peso 1.5 no consenso.
		Severity:       schema.SeverityCritical,
		Confidence:     schema.ConfidenceSignature,
		MatchedContent: schema.SanitizeSnippet(msg),
		ScanID:         raw.ScanID,
		DetectedAt:     detectedAt,
	}
}
