package schema

// Enums of the normalized schema. They all follow the same shape: a named
// string type, constants, and a Valid() used by validation. No value outside
// these sets reaches the verdict engine.

// Kind discriminates the nature of a finding. The MVP only produces
// KindMalware; the others exist because docs/schema-and-adapters.md section 3
// already defines them and feature 002 depends on them (see DECISIONS.md D-013).
type Kind string

const (
	// KindMalware is an already-installed malicious file. The only kind that
	// can be quarantined.
	KindMalware Kind = "malware"
	// KindVulnerability is a component with a known flaw. NEVER quarantined.
	KindVulnerability Kind = "vulnerability"
	// KindHardening is an insecure configuration.
	KindHardening Kind = "hardening"
)

func (k Kind) Valid() bool {
	switch k {
	case KindMalware, KindVulnerability, KindHardening:
		return true
	}
	return false
}

// Category is the finding taxonomy. Each adapter keeps its own rule→category
// table; anything unmapped becomes CategoryOther and is never discarded.
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

// Severity is the severity AS THE ENGINE SEES IT, normalized by the adapter.
// It is not the severity of the consolidated verdict.
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

// Confidence feeds the vote weight in the consensus.
type Confidence string

const (
	// ConfidenceSignature: exact hash or signature match.
	ConfidenceSignature Confidence = "signature"
	// ConfidenceHeuristic: pattern or behaviour.
	ConfidenceHeuristic Confidence = "heuristic"
	// ConfidenceAnomaly: out of the ordinary, with no signature.
	ConfidenceAnomaly Confidence = "anomaly"
)

func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceSignature, ConfidenceHeuristic, ConfidenceAnomaly:
		return true
	}
	return false
}

// ScanStatus is the outcome of one engine execution.
type ScanStatus string

const (
	StatusCompleted ScanStatus = "completed"
	// StatusPartial: finished, but with errors on some of the files.
	StatusPartial ScanStatus = "partial"
	StatusFailed  ScanStatus = "failed"
	StatusTimeout ScanStatus = "timeout"
	// StatusKilled: killed by a resource limit.
	StatusKilled ScanStatus = "killed"
)

func (s ScanStatus) Valid() bool {
	switch s {
	case StatusCompleted, StatusPartial, StatusFailed, StatusTimeout, StatusKilled:
		return true
	}
	return false
}

// CountsAsVote answers the central question of Principle VI: may this report
// count as "the engine found nothing"?
//
// Only StatusCompleted may. Any other status means the engine never got the
// chance to weigh in on every file, and an engine that did not weigh in
// abstains — it never votes innocent.
func (s ScanStatus) CountsAsVote() bool {
	return s == StatusCompleted
}

// ScanMode is the scope of the cycle.
type ScanMode string

const (
	ModeIncremental ScanMode = "incremental"
	ModeFull        ScanMode = "full"
	// ModeTargeted: an explicit path list (rescan after a hash mismatch).
	ModeTargeted ScanMode = "targeted"
)

func (m ScanMode) Valid() bool {
	switch m {
	case ModeIncremental, ModeFull, ModeTargeted:
		return true
	}
	return false
}

// Level is the level of the consolidated verdict.
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

// Rank allows levels to be ordered and compared (for alert filters such as
// "notify me about likely and above").
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

// AtLeast answers whether this level is as severe as another, or more.
func (l Level) AtLeast(other Level) bool {
	return l.Rank() >= other.Rank()
}

// ActionTaken records what the orchestrator did with the file. It is the field
// that answers "why was this file (not) quarantined?".
type ActionTaken string

const (
	// ActionNone: nothing to do (level below the action threshold).
	ActionNone ActionTaken = "none"
	// ActionQuarantined: moved to the vault, reversibly.
	ActionQuarantined ActionTaken = "quarantined"
	// ActionRecommended: would have been quarantined, but observation mode or
	// the grace period prevented it. The alert goes out as "action recommended".
	ActionRecommended ActionTaken = "recommended"
	// ActionSkippedWhitelist: the user put the file on the whitelist.
	ActionSkippedWhitelist ActionTaken = "skipped_whitelist"
	// ActionSkippedOfficial: the file matches the official WordPress checksum.
	ActionSkippedOfficial ActionTaken = "skipped_official_checksum"
	// ActionSkippedNotReachable: the file is not served by the web — it is in the
	// account's trash, or outside every document root.
	//
	// The verdict is unchanged and stays visible at its real level: this blocks the
	// ACTION only, the same way the whitelist does (D-006). Moving a file out of the
	// trash and into our vault swaps one holding area for another without reducing any
	// risk, and it takes the file further from where its owner expects to find it.
	//
	// It is emphatically not "safe". The trash restores with one click.
	ActionSkippedNotReachable ActionTaken = "skipped_not_reachable"
	// ActionRescanNeeded: the re-hash taken immediately before acting differed
	// from the verdict's hash. The file changed between scan and action, so it
	// gets rescanned instead of blindly quarantined (FR-018).
	ActionRescanNeeded ActionTaken = "rescan_needed"
	// ActionFailed: tried to quarantine and could not (disk full, no permission
	// on the vault). Becomes a critical alert, never a silent failure.
	ActionFailed ActionTaken = "failed"
	// ActionRestored: the user restored the file from the vault.
	ActionRestored ActionTaken = "restored"
	// ActionIgnored: the user ignored this finding once.
	ActionIgnored ActionTaken = "ignored"
)

func (a ActionTaken) Valid() bool {
	switch a {
	case ActionNone, ActionQuarantined, ActionRecommended,
		ActionSkippedWhitelist, ActionSkippedOfficial, ActionSkippedNotReachable,
		ActionRescanNeeded,
		ActionFailed, ActionRestored, ActionIgnored:
		return true
	}
	return false
}
