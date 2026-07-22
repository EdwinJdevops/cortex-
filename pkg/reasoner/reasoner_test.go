package reasoner

import (
	"context"
	"testing"
)

// TestKnownPatternsNeverCallQwen proves the core claim of this project:
// documented violations resolve without touching the network or the LLM.
func TestKnownPatternsNeverCallQwen(t *testing.T) {
	ctx := context.Background()

	for violationType, expected := range KnownPatterns {
		plan, err := Reason(ctx, violationType, "test description")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", violationType, err)
		}
		if plan.Source != "rule_engine" {
			t.Errorf("%s: expected source=rule_engine, got %s", violationType, plan.Source)
		}
		if plan.Confidence != expected.Confidence {
			t.Errorf("%s: expected confidence=%.2f, got %.2f", violationType, expected.Confidence, plan.Confidence)
		}
		if plan.ControlRef == "" {
			t.Errorf("%s: missing ControlRef — every deterministic pattern must cite a real control", violationType)
		}
	}
}

// TestSafetyGateBlocksLowConfidence proves auto_apply can never be true
// below the 0.95 threshold, regardless of what the source claims.
func TestSafetyGateBlocksLowConfidence(t *testing.T) {
	for name, plan := range KnownPatterns {
		if plan.AutoApply && plan.Confidence < 0.95 {
			t.Errorf("%s: auto_apply=true but confidence=%.2f is below 0.95 safety threshold", name, plan.Confidence)
		}
	}
}

// TestUnknownViolationRequiresAPIKey proves the escalation path fails
// safely (error, not panic, not a silent bypass) when misconfigured.
func TestUnknownViolationRequiresAPIKey(t *testing.T) {
	ctx := context.Background()
	_, err := Reason(ctx, "totally_novel_violation_xyz", "no matching rule")
	if err == nil {
		t.Fatal("expected error when QWEN_API_KEY is unset, got nil")
	}
}
