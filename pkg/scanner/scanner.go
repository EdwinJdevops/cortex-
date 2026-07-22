// Package scanner reads Kubernetes PolicyReport CRDs (the
// wgpolicyk8s.io standard) via kubectl. This is the actual integration
// point: Warden itself is a continuous in-cluster poller that watches
// these same PolicyReport objects and opens GitHub PRs — it has no
// on-demand "scan" CLI subcommand. Cortex reads the same source of
// truth Warden does, independently, rather than shelling out to Warden.
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

// policyReportList mirrors the subset of the wgpolicyk8s.io/v1alpha2
// PolicyReport schema this package needs.
type policyReportList struct {
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
		Results []struct {
			Policy    string `json:"policy"`
			Rule      string `json:"rule"`
			Result    string `json:"result"` // pass, fail, warn, error, skip
			Severity  string `json:"severity"`
			Message   string `json:"message"`
			Resources []struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"resources"`
		} `json:"results"`
	} `json:"items"`
}

// Scan reads PolicyReport objects from the cluster via kubectl and
// returns only failing results as violations. Requires kubectl to be
// installed and configured against the target cluster — this is a
// real dependency, not assumed away.
func Scan(namespace string) (*ScanResult, error) {
	start := time.Now()

	args := []string{"get", "policyreports.wgpolicyk8s.io", "-o", "json"}
	if namespace != "" && namespace != "all" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "-A")
	}

	cmd := exec.Command("kubectl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl get policyreports failed: %w — output: %s", err, string(out))
	}

	var reports policyReportList
	if err := json.Unmarshal(out, &reports); err != nil {
		return nil, fmt.Errorf("parse policyreport JSON: %w", err)
	}

	var violations []Violation
	for _, item := range reports.Items {
		for _, result := range item.Results {
			if result.Result != "fail" {
				continue
			}
			resourceID := item.Metadata.Namespace + "/" + item.Metadata.Name
			resourceType := "unknown"
			if len(result.Resources) > 0 {
				resourceType = result.Resources[0].Kind
				resourceID = item.Metadata.Namespace + "/" + result.Resources[0].Name
			}
			violations = append(violations, Violation{
				ResourceType: resourceType,
				ResourceID:   resourceID,
				PolicyName:   result.Policy + "/" + result.Rule,
				Severity:     result.Severity,
				Description:  result.Message,
				DetectedAt:   time.Now(),
			})
		}
	}

	return &ScanResult{
		Violations: violations,
		ScanTimeMs: time.Since(start).Milliseconds(),
		NodeCount:  len(violations),
	}, nil
}
