package compliance

import (
	"testing"
	"time"

	"github.com/amplify-lab/damping/core/event"
)

func TestSyntheticDemoDataset_SpansAboutThirtyDays(t *testing.T) {
	events := SyntheticDemoDataset()
	if len(events) == 0 {
		t.Fatal("expected a non-empty synthetic dataset")
	}
	oldest, newest := events[0].Timestamp, events[0].Timestamp
	for _, e := range events {
		if e.Timestamp.Before(oldest) {
			oldest = e.Timestamp
		}
		if e.Timestamp.After(newest) {
			newest = e.Timestamp
		}
	}
	span := newest.Sub(oldest)
	if span < 20*24*time.Hour || span > 31*24*time.Hour {
		t.Fatalf("expected the synthetic dataset to span roughly 30 days, got a span of %v (oldest=%v newest=%v)", span, oldest, newest)
	}
}

// TestSyntheticDemoDataset_EveryRuleIDIsReal guards against the demo ever
// drifting from what Damping actually ships — a demo report citing a rule
// id that doesn't exist in cli/policies/default.yaml would be actively
// misleading in a sales conversation, not just cosmetically wrong.
func TestSyntheticDemoDataset_EveryRuleIDIsReal(t *testing.T) {
	realRuleIDs := map[string]bool{
		"destructive.rm_rf_protected":              true,
		"destructive.git_push_force":               true,
		"destructive.sql_drop_truncate":            true,
		"destructive.chmod_777_recursive":          true,
		"destructive.curl_pipe_sh_unallowlisted":   true,
		"destructive.encoded_payload_pipe":         true,
		"destructive.proc_sandbox_bypass":          true,
		"destructive.dynamic_command_construction": true,
		"destructive.write_protected_path":         true,
		"mcp.destructive_tool_call":                true,
		"self_protection.damping_off_attempt":      true,
		"destructive.iac_destroy":                  true,
		"destructive.iac_apply_unreviewed":         true,
		"destructive.git_history_destructive":      true,
		"destructive.secret_exfiltration":          true,
		"destructive.agent_permission_escalation":  true,
		"destructive.git_hook_write":               true,
		"destructive.npm_lifecycle_script_write":   true,
		"destructive.kubectl_bulk_delete":          true,
		"destructive.cloud_cli_mass_delete":        true,
		"destructive.raw_device_write":             true,
		"destructive.cargo_publish_unreviewed":     true,
		"destructive.gem_push_unreviewed":          true,
		"destructive.webhook_exfiltration":         true,
	}
	for _, e := range SyntheticDemoDataset() {
		if e.Decision.PolicyID == "" {
			continue // a plain allow with no matched rule is fine
		}
		if !realRuleIDs[e.Decision.PolicyID] {
			t.Errorf("synthetic demo event references rule id %q, which is not in cli/policies/default.yaml's real rule set", e.Decision.PolicyID)
		}
	}
}

func TestSyntheticDemoDataset_MixesActorsChannelsAndOutcomes(t *testing.T) {
	events := SyntheticDemoDataset()
	actors := map[string]bool{}
	channels := map[event.Channel]bool{}
	outcomes := map[string]bool{}
	boundIdentities := 0
	for _, e := range events {
		actors[e.Actor] = true
		channels[e.Channel] = true
		outcomes[string(e.Decision.Outcome())] = true
		if e.Identity != "" {
			boundIdentities++
		}
	}
	if len(actors) < 2 {
		t.Fatalf("expected multiple distinct actors in the demo dataset, got %d", len(actors))
	}
	if len(outcomes) < 2 {
		t.Fatalf("expected a mix of outcomes (not all deny or all allow), got %v", outcomes)
	}
	if boundIdentities == 0 {
		t.Fatal("expected at least some synthetic events to carry a bound identity (simulating the Phase 5 AD/LDAP-bound view), got none")
	}
}

func TestSyntheticDemoDataset_EveryEventValidatesAsARealActionEvent(t *testing.T) {
	for _, e := range SyntheticDemoDataset() {
		if err := e.Validate(); err != nil {
			t.Errorf("synthetic event %q fails ActionEvent.Validate(): %v", e.EventID, err)
		}
	}
}
