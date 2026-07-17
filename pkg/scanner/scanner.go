package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

type Violation struct {
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	PolicyName   string    `json:"policy_name"`
	Severity     string    `json:"severity"`
	Description  string    `json:"description"`
	DetectedAt   time.Time `json:"detected_at"`
}

type ScanResult struct {
	Violations []Violation `json:"violations"`
	ScanTimeMs int64       `json:"scan_time_ms"`
	NodeCount  int         `json:"node_count"`
}

// Scan invokes Warden CLI as subprocess, parses JSON output.
// Deterministic: no LLM call here. Pure detection.
func Scan(namespace string) (*ScanResult, error) {
	start := time.Now()

	cmd := exec.Command("warden", "scan", "--namespace", namespace, "--output", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("warden scan failed: %w", err)
	}

	var violations []Violation
	if err := json.Unmarshal(out, &violations); err != nil {
		return nil, fmt.Errorf("parse warden output: %w", err)
	}

	return &ScanResult{
		Violations: violations,
		ScanTimeMs: time.Since(start).Milliseconds(),
		NodeCount:  len(violations),
	}, nil
}
