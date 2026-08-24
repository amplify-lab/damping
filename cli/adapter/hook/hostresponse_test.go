package hook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// TestBuildHostResponse_AllowNeverAutoApproves is the load-bearing test in
// this file. In the Claude Code hook contract, permissionDecision "allow"
// means "skip the host's own permission flow" — so emitting it would have
// Damping approving actions on the user's behalf, including ones the host's
// own policy would have stopped. "Damping has no objection" is a different
// statement from "approved", and only the first is a guardrail's to make.
func TestBuildHostResponse_AllowNeverAutoApproves(t *testing.T) {
	for _, dialect := range []HostDialect{DialectClaudeCode, DialectCursor} {
		resp := BuildHostResponse(HostResponseInput{
			Dialect:  dialect,
			Decision: decision.Decision{Verdict: decision.Allow},
			EventID:  "evt_1",
		})
		if resp.HookSpecificOutput != nil {
			t.Errorf("%s: expected no hookSpecificOutput for an allow, got %+v", dialect, resp.HookSpecificOutput)
		}
		if resp.Permission != "" {
			t.Errorf("%s: expected no permission field for an allow, got %q", dialect, resp.Permission)
		}
		if resp.Damping.Decision != HostDecisionAllow {
			t.Errorf("%s: damping.decision = %q, want %q", dialect, resp.Damping.Decision, HostDecisionAllow)
		}
	}
}

func TestBuildHostResponse_DeferredPromptBecomesAsk(t *testing.T) {
	resp := BuildHostResponse(HostResponseInput{
		Dialect: DialectClaudeCode,
		Decision: decision.Decision{
			Verdict:  decision.Prompt,
			PolicyID: "destructive.rm_rf_protected",
			Risk:     "critical",
			Reason:   "would destroy irreplaceable data",
		},
		Deferred:   true,
		EventID:    "evt_2",
		Channel:    event.ChannelCLI,
		ActionType: event.ActionShellExec,
		Target:     "~/",
		Version:    "1.2.3",
	})

	if resp.HookSpecificOutput == nil || resp.HookSpecificOutput.PermissionDecision != HostDecisionAsk {
		t.Fatalf("expected permissionDecision %q, got %+v", HostDecisionAsk, resp.HookSpecificOutput)
	}
	if resp.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", resp.HookSpecificOutput.HookEventName)
	}
	if resp.HookSpecificOutput.PermissionDecisionReason != "would destroy irreplaceable data" {
		t.Errorf("the host has to be able to tell the human why: reason = %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
	if resp.Damping.Decision != HostDecisionAsk {
		t.Errorf("damping.decision = %q, want %q", resp.Damping.Decision, HostDecisionAsk)
	}
	// Verdict stays the raw policy verdict: "ask" is what the host must do,
	// "prompt" is what the policy said.
	if resp.Damping.Verdict != string(decision.Prompt) {
		t.Errorf("damping.verdict = %q, want %q", resp.Damping.Verdict, decision.Prompt)
	}
	if resp.Damping.PolicyID != "destructive.rm_rf_protected" || resp.Damping.Risk != "critical" {
		t.Errorf("expected the matched rule and its risk to reach the host, got %+v", resp.Damping)
	}
	if resp.Damping.EventID != "evt_2" || resp.Damping.Target != "~/" || resp.Damping.Version != "1.2.3" {
		t.Errorf("expected event id, target, and version to reach the host, got %+v", resp.Damping)
	}
}

func TestBuildHostResponse_Deny(t *testing.T) {
	d := decision.Decision{Verdict: decision.Deny, PolicyID: "self_protection.damping_off_attempt", Reason: "no"}
	resp := BuildHostResponse(HostResponseInput{Dialect: DialectClaudeCode, Decision: d})
	if resp.HookSpecificOutput == nil || resp.HookSpecificOutput.PermissionDecision != HostDecisionDeny {
		t.Fatalf("expected permissionDecision %q, got %+v", HostDecisionDeny, resp.HookSpecificOutput)
	}
	if resp.Damping.Decision != HostDecisionDeny {
		t.Errorf("damping.decision = %q, want %q", resp.Damping.Decision, HostDecisionDeny)
	}
}

// TestBuildHostResponse_DenyResolvedFromAPrompt: a prompt the user (or an
// operator's noninteractive_prompt_fallback) resolved to deny is a deny to
// the host — Outcome(), not Verdict, decides.
func TestBuildHostResponse_DenyResolvedFromAPrompt(t *testing.T) {
	d := decision.Decision{Verdict: decision.Prompt, Reason: "flagged"}
	d.Resolve(decision.Deny)
	resp := BuildHostResponse(HostResponseInput{Dialect: DialectClaudeCode, Decision: d})
	if resp.Damping.Decision != HostDecisionDeny {
		t.Errorf("damping.decision = %q, want %q", resp.Damping.Decision, HostDecisionDeny)
	}
}

func TestBuildHostResponse_CursorDialect(t *testing.T) {
	resp := BuildHostResponse(HostResponseInput{
		Dialect:  DialectCursor,
		Decision: decision.Decision{Verdict: decision.Prompt, Reason: "flagged"},
		Deferred: true,
	})
	if resp.HookSpecificOutput != nil {
		t.Errorf("expected no Claude-Code-shaped block in the Cursor dialect, got %+v", resp.HookSpecificOutput)
	}
	if resp.Permission != HostDecisionAsk || resp.UserMessage != "flagged" || resp.AgentMessage != "flagged" {
		t.Errorf("expected Cursor's permission/user_message/agent_message shape, got %+v", resp)
	}
}

func TestWriteHostResponse_IsOneParseableLine(t *testing.T) {
	var sb strings.Builder
	resp := BuildHostResponse(HostResponseInput{
		Dialect:  DialectClaudeCode,
		Decision: decision.Decision{Verdict: decision.Allow, Degraded: true, Reason: "policy file unreadable"},
	})
	if err := WriteHostResponse(&sb, resp); err != nil {
		t.Fatalf("WriteHostResponse: %v", err)
	}
	out := sb.String()
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Errorf("expected exactly one line so a host can read a single response per invocation, got:\n%s", out)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("parsing %q: %v", out, err)
	}
	damping, ok := decoded["damping"].(map[string]any)
	if !ok {
		t.Fatalf("expected a damping block, got %v", decoded)
	}
	if damping["degraded"] != true {
		t.Errorf("a degraded run must say so — the host cannot otherwise tell 'allowed' from 'not running': %v", damping)
	}
}
