package cycle

import (
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// A cycle where nothing voted must never look like a cycle that found nothing.
//
// `ScanStatus.CountsAsVote()` enforces this one level down: an engine that could not run
// abstains rather than reporting zero findings. The cycle had no equivalent, so four
// abstentions out of four still produced `status: completed`, `verdicts: {}` and exit
// code 0 — indistinguishable, to the panel or to a webhook consumer or to any monitoring
// check, from "scanned everything, site is clean".
//
// The human-readable output did say coverage was reduced. JSON, exit codes and the store
// did not, and those are the interfaces nobody reads a sentence in.

func TestACycleWhereNoEngineVotedIsNotCompleted(t *testing.T) {
	s := &Summary{Engines: []EngineOutcome{
		{Slug: "amwscan", Available: false, Reason: "PHP CLI not found"},
		{Slug: "maldet", Available: false, Reason: "binary not found"},
		{Slug: "php-malware-finder", Available: false, Reason: "yara not on PATH"},
		{Slug: "wp-checksums", Available: false, Reason: "not a WordPress installation"},
	}}
	if s.AnyEngineVoted() {
		t.Fatal("no engine was available, yet the cycle claims one voted")
	}
}

// One working engine is a real scan whose result is incomplete, not absent. Marking those
// partial too would make `partial` the permanent state of every host without yara and
// maldet installed — which is most of them — and a status that is always on carries no
// information.
func TestOneWorkingEngineIsEnoughToCountAsAScan(t *testing.T) {
	s := &Summary{Engines: []EngineOutcome{
		{Slug: "wp-checksums", Available: true, Status: schema.StatusCompleted},
		{Slug: "maldet", Available: false, Reason: "binary not found"},
		{Slug: "php-malware-finder", Available: false, Reason: "yara not on PATH"},
	}}
	if !s.AnyEngineVoted() {
		t.Error("one engine completed, so the cycle did scan something")
	}
}

// An engine that was AVAILABLE and then failed, timed out or was killed did not vote
// either. Availability alone is not participation — that distinction is the whole point
// of CountsAsVote, and reading only `Available` here would reintroduce the bug for the
// case that matters most: an engine that starts, dies halfway and reports nothing.
func TestAnAvailableEngineThatFailedDoesNotCountAsAVote(t *testing.T) {
	for _, st := range []schema.ScanStatus{
		schema.StatusFailed, schema.StatusTimeout, schema.StatusKilled,
	} {
		s := &Summary{Engines: []EngineOutcome{
			{Slug: "amwscan", Available: true, Status: st},
		}}
		if s.AnyEngineVoted() {
			t.Errorf("status %q counts as a vote: an engine that did not finish looking "+
				"cannot make an empty result mean anything", st)
		}
	}
}

// A partial engine report DOES count: it looked at part of the tree and what it found
// there is real. Discarding it would throw away findings the engine actually made.
func TestAPartialEngineReportStillCounts(t *testing.T) {
	s := &Summary{Engines: []EngineOutcome{
		{Slug: "amwscan", Available: true, Status: schema.StatusPartial},
	}}
	if !s.AnyEngineVoted() != !schema.StatusPartial.CountsAsVote() {
		t.Errorf("the cycle and the engine disagree about whether %q is a vote",
			schema.StatusPartial)
	}
}

// An empty cycle — no engines at all, e.g. every one disabled in the configuration —
// scanned nothing by definition.
func TestACycleWithNoEnginesAtAllDidNotScan(t *testing.T) {
	if (&Summary{}).AnyEngineVoted() {
		t.Error("a cycle with no engines claims one voted")
	}
}
