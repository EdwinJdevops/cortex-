package reasoner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type RemediationPlan struct {
	Action     string  `json:"action"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"` // "rule_engine" or "qwen_llm"
	Reasoning  string  `json:"reasoning"`
	AutoApply  bool    `json:"auto_apply"`
	ControlRef string  `json:"control_ref,omitempty"` // CIS/NSA control mapping
}

// KnownPatterns is the deterministic rule table, mapped to CIS Kubernetes
// Benchmark v1.8 and NSA/CISA Kubernetes Hardening Guidance controls.
// Every entry here is a documented, auditable security control — not a
// guess. Confidence reflects how unambiguous the fix is, not how "sure"
// a model feels.
var KnownPatterns = map[string]RemediationPlan{
	"privileged_container": {
		Action:     "set securityContext.privileged=false",
		Confidence: 0.99,
		Source:     "rule_engine",
		AutoApply:  true,
		ControlRef: "CIS 5.2.1",
	},
	"missing_resource_limits": {
		Action:     "apply ResourceQuota + LimitRange from namespace baseline",
		Confidence: 0.97,
		Source:     "rule_engine",
		AutoApply:  true,
		ControlRef: "CIS 5.7.1",
	},
	"exposed_secret": {
		Action:     "rotate secret + revoke old value, alert security team",
		Confidence: 1.0,
		Source:     "rule_engine",
		AutoApply:  false, // human sign-off required for secret rotation
		ControlRef: "CIS 5.4.1",
	},
	"host_network_enabled": {
		Action:     "set hostNetwork=false unless explicitly allowlisted",
		Confidence: 0.96,
		Source:     "rule_engine",
		AutoApply:  false, // may break legitimate CNI/monitoring pods
		ControlRef: "CIS 5.2.4",
	},
	"host_pid_enabled": {
		Action:     "set hostPID=false",
		Confidence: 0.98,
		Source:     "rule_engine",
		AutoApply:  true,
		ControlRef: "CIS 5.2.2",
	},
	"allow_privilege_escalation": {
		Action:     "set securityContext.allowPrivilegeEscalation=false",
		Confidence: 0.99,
		Source:     "rule_engine",
		AutoApply:  true,
		ControlRef: "CIS 5.2.5",
	},
	"root_filesystem_writable": {
		Action:     "set securityContext.readOnlyRootFilesystem=true",
		Confidence: 0.90,
		Source:     "rule_engine",
		AutoApply:  false, // some apps legitimately need writable rootfs
		ControlRef: "CIS 5.2.6",
	},
	"default_service_account_mounted": {
		Action:     "set automountServiceAccountToken=false unless pod needs API access",
		Confidence: 0.93,
		Source:     "rule_engine",
		AutoApply:  false,
		ControlRef: "CIS 5.1.5",
	},
	"wildcard_rbac_permissions": {
		Action:     "flag Role/ClusterRole for manual review — never auto-narrow RBAC",
		Confidence: 1.0,
		Source:     "rule_engine",
		AutoApply:  false, // auto-editing RBAC can lock out legitimate access
		ControlRef: "CIS 5.1.3",
	},
	"unpinned_image_tag": {
		Action:     "flag :latest or missing digest pin for CI pipeline review",
		Confidence: 0.85,
		Source:     "rule_engine",
		AutoApply:  false,
		ControlRef: "NSA-CISA Hardening Guide 4.2",
	},
}

type qwenRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	MaxTokens int `json:"max_tokens"`
}

type qwenResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Reason decides remediation. Deterministic-first: only calls Qwen
// when the violation doesn't match a known CIS/NSA-mapped pattern.
// This keeps token spend near zero and latency in the millisecond
// range for the large majority of real-world violations, and keeps
// every deterministic action traceable to a named security control
// rather than model judgment.
func Reason(ctx context.Context, violationType, description string) (*RemediationPlan, error) {
	if plan, ok := KnownPatterns[violationType]; ok {
		plan.Reasoning = fmt.Sprintf("matched deterministic pattern (%s), no LLM call", plan.ControlRef)
		return &plan, nil
	}

	return reasonWithQwen(ctx, violationType, description)
}

func reasonWithQwen(ctx context.Context, violationType, description string) (*RemediationPlan, error) {
	apiKey := os.Getenv("QWEN_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("QWEN_API_KEY not set")
	}

	reqBody := qwenRequest{
		Model: "qwen-max",
		Messages: []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{
			{Role: "system", Content: "You are a Kubernetes security remediation engine. Respond ONLY with JSON: {\"action\": string, \"confidence\": float 0-1, \"auto_apply\": bool}. auto_apply must be false unless confidence >= 0.95 and the action is fully reversible. This is a novel violation pattern with no matching CIS/NSA control — be conservative."},
			{Role: "user", Content: fmt.Sprintf("Violation type: %s\nDescription: %s\nRecommend remediation.", violationType, description)},
		},
		MaxTokens: 300,
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qwen request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("qwen returned status %d", resp.StatusCode)
	}

	var qResp qwenResponse
	if err := json.NewDecoder(resp.Body).Decode(&qResp); err != nil {
		return nil, err
	}
	if len(qResp.Choices) == 0 {
		return nil, fmt.Errorf("empty qwen response")
	}

	var plan RemediationPlan
	if err := json.Unmarshal([]byte(qResp.Choices[0].Message.Content), &plan); err != nil {
		return nil, fmt.Errorf("qwen returned non-JSON: %w", err)
	}
	plan.Source = "qwen_llm"
	plan.Reasoning = "novel violation pattern, no CIS/NSA control match, escalated to LLM reasoning"

	// Hard safety gate: LLM output never gets the same trust ceiling as
	// a named, documented security control.
	if plan.Confidence < 0.95 {
		plan.AutoApply = false
	}

	return &plan, nil
}
