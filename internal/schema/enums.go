package schema

// Enums do esquema normalizado. Todos seguem o mesmo padrao: tipo string
// nomeado, constantes, e um Valid() usado pela validacao. Nenhum valor fora
// destes conjuntos entra no motor de veredito.

// Kind discrimina a natureza do achado. O MVP so produz KindMalware; os
// demais existem porque docs/esquema-e-adaptadores.md secao 3 ja os define e
// a feature 002 depende deles (ver DECISIONS.md D-013).
type Kind string

const (
	// KindMalware e um arquivo malicioso ja instalado. Unico que pode ser
	// quarentenado.
	KindMalware Kind = "malware"
	// KindVulnerability e um componente com falha conhecida. NUNCA quarentena.
	KindVulnerability Kind = "vulnerability"
	// KindHardening e uma configuracao insegura.
	KindHardening Kind = "hardening"
)

func (k Kind) Valid() bool {
	switch k {
	case KindMalware, KindVulnerability, KindHardening:
		return true
	}
	return false
}

// Category e a taxonomia de achados. Cada adaptador mantem sua propria tabela
// regra->categoria; o que nao mapear vira CategoryOther, nunca e descartado.
type Category string

const (
	CategoryKnownMalware        Category = "known_malware"
	CategoryObfuscation         Category = "obfuscation"
	CategoryBackdoor            Category = "backdoor"
	CategoryWebshell            Category = "webshell"
	CategoryInjection           Category = "injection"
	CategorySpamSEO             Category = "spam_seo"
	CategoryPhishing            Category = "phishing"
	CategoryDropper             Category = "dropper"
	CategoryCoreIntegrity       Category = "core_integrity"
	CategorySuspiciousLocation  Category = "suspicious_location"
	CategorySuspiciousPerms     Category = "suspicious_perms"
	CategoryVulnerableComponent Category = "vulnerable_component"
	CategoryOther               Category = "other"
)

func (c Category) Valid() bool {
	switch c {
	case CategoryKnownMalware, CategoryObfuscation, CategoryBackdoor,
		CategoryWebshell, CategoryInjection, CategorySpamSEO,
		CategoryPhishing, CategoryDropper, CategoryCoreIntegrity,
		CategorySuspiciousLocation, CategorySuspiciousPerms,
		CategoryVulnerableComponent, CategoryOther:
		return true
	}
	return false
}

// Severity e a severidade NA VISAO DO ENGINE, normalizada pelo adaptador.
// Nao e a severidade do veredito consolidado.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// Confidence alimenta o peso do voto no consenso.
type Confidence string

const (
	// ConfidenceSignature: hash ou assinatura exata.
	ConfidenceSignature Confidence = "signature"
	// ConfidenceHeuristic: padrao ou comportamento.
	ConfidenceHeuristic Confidence = "heuristic"
	// ConfidenceAnomaly: fora do padrao, sem assinatura.
	ConfidenceAnomaly Confidence = "anomaly"
)

func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceSignature, ConfidenceHeuristic, ConfidenceAnomaly:
		return true
	}
	return false
}

// ScanStatus e o desfecho da execucao de um engine.
type ScanStatus string

const (
	StatusCompleted ScanStatus = "completed"
	// StatusPartial: terminou, mas com erros em parte dos arquivos.
	StatusPartial ScanStatus = "partial"
	StatusFailed  ScanStatus = "failed"
	StatusTimeout ScanStatus = "timeout"
	// StatusKilled: morto por limite de recursos.
	StatusKilled ScanStatus = "killed"
)

func (s ScanStatus) Valid() bool {
	switch s {
	case StatusCompleted, StatusPartial, StatusFailed, StatusTimeout, StatusKilled:
		return true
	}
	return false
}

// CountsAsVote responde a pergunta central do Principio VI: este relatorio
// pode contar como "o engine nao achou nada"?
//
// So StatusCompleted pode. Qualquer outro status significa que o engine nao
// teve chance de opinar sobre todos os arquivos, e um engine que nao opinou
// abstem-se — nunca vota limpo.
func (s ScanStatus) CountsAsVote() bool {
	return s == StatusCompleted
}

// ScanMode e o escopo do ciclo.
type ScanMode string

const (
	ModeIncremental ScanMode = "incremental"
	ModeFull        ScanMode = "full"
	// ModeTargeted: lista explicita de caminhos (rescan apos re-hash divergente).
	ModeTargeted ScanMode = "targeted"
)

func (m ScanMode) Valid() bool {
	switch m {
	case ModeIncremental, ModeFull, ModeTargeted:
		return true
	}
	return false
}

// Level e o nivel do veredito consolidado.
type Level string

const (
	LevelConfirmed  Level = "confirmed"
	LevelLikely     Level = "likely"
	LevelSuspicious Level = "suspicious"
	LevelClean      Level = "clean"
)

func (l Level) Valid() bool {
	switch l {
	case LevelConfirmed, LevelLikely, LevelSuspicious, LevelClean:
		return true
	}
	return false
}

// Rank permite ordenar e comparar niveis (para filtros de alerta do tipo
// "me avise de likely para cima").
func (l Level) Rank() int {
	switch l {
	case LevelConfirmed:
		return 3
	case LevelLikely:
		return 2
	case LevelSuspicious:
		return 1
	case LevelClean:
		return 0
	}
	return -1
}

// AtLeast responde se este nivel e tao ou mais grave que outro.
func (l Level) AtLeast(other Level) bool {
	return l.Rank() >= other.Rank()
}

// ActionTaken registra o que o orquestrador fez com o arquivo. E o campo que
// responde "por que este arquivo (nao) foi quarentenado?".
type ActionTaken string

const (
	// ActionNone: nada a fazer (nivel abaixo do limiar de acao).
	ActionNone ActionTaken = "none"
	// ActionQuarantined: movido para o cofre, reversivelmente.
	ActionQuarantined ActionTaken = "quarantined"
	// ActionRecommended: seria quarentenado, mas modo observacao ou periodo
	// de graca impediram. O alerta sai como "acao recomendada".
	ActionRecommended ActionTaken = "recommended"
	// ActionSkippedWhitelist: usuario colocou o arquivo na whitelist.
	ActionSkippedWhitelist ActionTaken = "skipped_whitelist"
	// ActionSkippedOfficial: arquivo bate com checksum oficial do WordPress.
	ActionSkippedOfficial ActionTaken = "skipped_official_checksum"
	// ActionRescanNeeded: o re-hash imediatamente antes de agir divergiu do
	// hash do veredito. O arquivo mudou entre o scan e a acao; reescaneia em
	// vez de quarentenar as cegas (FR-018).
	ActionRescanNeeded ActionTaken = "rescan_needed"
	// ActionFailed: tentou quarentenar e nao conseguiu (disco cheio, sem
	// permissao no cofre). Vira alerta critico, nunca falha silenciosa.
	ActionFailed ActionTaken = "failed"
	// ActionRestored: usuario restaurou o arquivo do cofre.
	ActionRestored ActionTaken = "restored"
	// ActionIgnored: usuario ignorou este achado uma vez.
	ActionIgnored ActionTaken = "ignored"
)

func (a ActionTaken) Valid() bool {
	switch a {
	case ActionNone, ActionQuarantined, ActionRecommended,
		ActionSkippedWhitelist, ActionSkippedOfficial, ActionRescanNeeded,
		ActionFailed, ActionRestored, ActionIgnored:
		return true
	}
	return false
}
