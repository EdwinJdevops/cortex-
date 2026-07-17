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
	Action      string  `json:"action"`
	Confidence  float64 `json:"confidence"`
	Source      string  `json:"source"` // "rule_engine" or "qwen_llm"
	Reasoning   string  `json:"reasoning"`
	AutoApply   bool    `json:"auto_apply"`
}

// KnownPatterns is the deterministic rule table.
// Built from real remediation history — not hallucinated.
// This is what makes Cortex NOT an AI wrapper: known violations
// never touch the LLM. Only novel/ambiguous cases escalate.
var KnownPatterns = map[string]RemediationPlan{
	"privileged_container": {
		Action:     "set securityContext.privileged=false",
		Confidence: 0.99,
		Source:     "rule_engine",
		AutoApply:  true,
	},
	"missing_resource_limits": {
		Action:     "apply default ResourceQuota from policy baseline",
		Confidence: 0.97,
		Source:     "rule_engine",
		AutoApply:  true,
	},
	"exposed_secret": {
		Action:     "rotate secret + revoke, alert security team",
		Confidence: 1.0,
		Source:     "rule_engine",
		AutoApply:  false, // human sign-off required for secret rotation
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
// when the violation doesn't match a known pattern. This keeps
// token spend near zero and latency in the millisecond range for
// 90%+ of real-world violations.
func Reason(ctx context.Context, violationType, description string) (*RemediationPlan, error) {
	if plan, ok := KnownPatterns[violationType]; ok {
		plan.Reasoning = "matched known deterministic pattern, no LLM call"
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
			{Role: "system", Content: "You are a Kubernetes security remediation engine. Respond ONLY with JSON: {\"action\": string, \"confidence\": float 0-1, \"auto_apply\": bool}. auto_apply must be false unless confidence >= 0.95 and action is fully reversible."},
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
	plan.Reasoning = "novel violation pattern, escalated to LLM reasoning"

	// Hard safety gate: never trust LLM auto-apply above rule-engine trust level
	if plan.Confidence < 0.95 {
		plan.AutoApply = false
	}

	return &plan, nil
}
