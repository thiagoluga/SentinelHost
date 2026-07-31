package verdict_test

import (
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/reach"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

// Where a file sits changes what the tool DOES, never what it says.
//
// The distinction exists because a webshell in the document root can be executed by
// anyone with the URL this minute, and the same webshell in the account's trash cannot be
// executed by anybody. That is a real difference in urgency, and a person deciding what
// to look at first needs it.
//
// It is deliberately kept out of the score. Adjusting a verdict by context is the
// mechanism through which real findings quietly stop being seen, and it is the one thing
// this whole project is organised against. What the classification feeds is the ACTION,
// which is exactly where the whitelist acts too (D-006).

const shaX = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func verdictFor(t *testing.T, path string, cls *reach.Classifier) schema.Verdict {
	t.Helper()
	res := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("wp-checksums", finding("wp-checksums", "core_file_unexpected", shaX, path, schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "EVAL_POST", shaX, path, schema.ConfidenceSignature)),
		},
		Reach: cls,
		Now:   time.Unix(1785000000, 0),
	})
	if len(res.Verdicts) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(res.Verdicts))
	}
	return res.Verdicts[0]
}

func TestAFindingInTheTrashKeepsItsLevelAndIsNotActedOn(t *testing.T) {
	cls := reach.New([]string{"/home/u/public_html"}, nil)
	v := verdictFor(t, "/home/u/.trash/wordpress/wp-admin/includes/update-core-helper.php", cls)

	// The verdict itself is untouched. Two signature votes still reach confirmed, and
	// the level is what the report shows and what the alerts carry.
	if v.Level != schema.LevelConfirmed {
		t.Errorf("level %q: the location must not change the verdict, only the action", v.Level)
	}
	if v.Score < 0.9 {
		t.Errorf("score %.2f was reduced by the location", v.Score)
	}
	if len(v.Votes) != 2 {
		t.Errorf("%d vote(s): the votes are the evidence and must survive intact", len(v.Votes))
	}

	// What changes is that the tool does not move it by itself.
	if v.ActionTaken != schema.ActionSkippedNotReachable {
		t.Errorf("action %q, want skipped_not_reachable: moving a file out of the trash and "+
			"into our vault swaps one holding area for another", v.ActionTaken)
	}
	if v.FileLocation != string(reach.LocationTrash) {
		t.Errorf("file_location %q, want trash", v.FileLocation)
	}
	// And the reason has to say what "unreachable" does NOT mean.
	if v.ActionError == "" {
		t.Fatal("no reason recorded for skipping the action")
	}
	if !contains(v.ActionError, "restore") {
		t.Errorf("the reason does not mention that the trash restores with one click, which "+
			"is the half of the message that stops this reading as \"safe\": %q", v.ActionError)
	}
}

// The case that must NOT be sheltered: a file the web actually serves.
func TestAFindingInTheDocumentRootIsStillActedOn(t *testing.T) {
	cls := reach.New([]string{"/home/u/public_html"}, nil)
	v := verdictFor(t, "/home/u/public_html/wp-content/uploads/shell.php", cls)

	if v.ActionTaken == schema.ActionSkippedNotReachable {
		t.Error("a file inside the document root was treated as unreachable — this is the " +
			"one a visitor can execute right now")
	}
	if v.FileLocation != string(reach.LocationWebReachable) {
		t.Errorf("file_location %q, want web_reachable", v.FileLocation)
	}
}

// "This IS served" is the half of the answer that makes a finding urgent, so it is
// recorded on every verdict. A field that only appeared for the sheltered cases would
// read as a badge for harmless results.
func TestTheLocationIsRecordedEvenWhenItIsReachable(t *testing.T) {
	cls := reach.New([]string{"/home/u/public_html"}, nil)
	if v := verdictFor(t, "/home/u/public_html/x.php", cls); v.FileLocation == "" {
		t.Error("no location on a served file")
	}
}

// With no classifier, nothing is claimed and nothing is sheltered. That is the state of
// every installation that has not configured document roots, and it must behave exactly
// as the tool did before this existed.
func TestWithoutAClassifierEverythingBehavesAsBefore(t *testing.T) {
	v := verdictFor(t, "/home/u/.trash/wordpress/x.php", nil)

	if v.ActionTaken == schema.ActionSkippedNotReachable {
		t.Error("a verdict was sheltered with no classifier configured")
	}
	if v.FileLocation != "" {
		t.Errorf("file_location %q was set with no classifier", v.FileLocation)
	}
}

// An explicit whitelist entry is something the user wrote themselves, so it is the reason
// shown when both apply — they should see their own rule, not an inference of ours.
func TestAnExplicitWhitelistRuleIsTheReasonShown(t *testing.T) {
	cls := reach.New([]string{"/home/u/public_html"}, nil)
	res := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("wp-checksums", finding("wp-checksums", "core_file_unexpected", shaX,
				"/home/u/.trash/x.php", schema.ConfidenceSignature)),
		},
		Whitelist: []string{"**/.trash/**"},
		Reach:     cls,
		Now:       time.Unix(1785000000, 0),
	})
	if res.Verdicts[0].ActionTaken != schema.ActionSkippedWhitelist {
		t.Errorf("action %q: the user's own rule should be the reason they are shown",
			res.Verdicts[0].ActionTaken)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
