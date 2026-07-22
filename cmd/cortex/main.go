package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/EdwinJdevops/cortex/pkg/reasoner"
	"github.com/EdwinJdevops/cortex/pkg/scanner"
)

// AuditEntry is the immutable record of every decision Cortex makes.
// Nothing happens silently — every plan, applied or not, has a paper trail.
type AuditEntry struct {
	Timestamp time.Time                 `json:"timestamp"`
	Violation scanner.Violation         `json:"violation"`
	Plan      *reasoner.RemediationPlan `json:"plan"`
	Applied   bool                      `json:"applied"`
	Error     string                    `json:"error,omitempty"`
}

func main() {
	namespace := flag.String("namespace", "default", "Kubernetes namespace to scan")
	dryRun := flag.Bool("dry-run", true, "If true, never auto-apply, only report")
	auditPath := flag.String("audit-log", "cortex-audit.jsonl", "Path to append-only audit log")
	fixturePath := flag.String("fixture", "", "Path to a fixture JSON file of violations, bypasses live Warden scan entirely — use this to try Cortex without a Kubernetes cluster")
	flag.Parse()

	ctx := context.Background()

	var violations []scanner.Violation
	var scanTimeMs int64

	if *fixturePath != "" {
		fmt.Printf("[cortex] loading fixture=%s (no live cluster contacted)\n", *fixturePath)
		data, err := os.ReadFile(*fixturePath)
		if err != nil {
			log.Fatalf("cannot read fixture: %v", err)
		}
		if err := json.Unmarshal(data, &violations); err != nil {
			log.Fatalf("fixture is not valid JSON matching scanner.Violation: %v", err)
		}
	} else {
		fmt.Printf("[cortex] scanning namespace=%s\n", *namespace)
		result, err := scanner.Scan(*namespace)
		if err != nil {
			log.Fatalf("scan failed: %v", err)
		}
		violations = result.Violations
		scanTimeMs = result.ScanTimeMs
	}

	fmt.Printf("[cortex] %d violations to reason about\n", len(violations))

	auditFile, err := os.OpenFile(*auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("cannot open audit log: %v", err)
	}
	defer auditFile.Close()

	for _, v := range violations {
		plan, err := reasoner.Reason(ctx, v.PolicyName, v.Description)
		entry := AuditEntry{
			Timestamp: time.Now(),
			Violation: v,
			Plan:      plan,
		}

		if err != nil {
			entry.Error = err.Error()
			fmt.Printf("[cortex] REASONING FAILED for %s: %v\n", v.ResourceID, err)
		} else {
			fmt.Printf("[cortex] %s -> action=%q confidence=%.2f source=%s control=%s auto_apply=%v\n",
				v.ResourceID, plan.Action, plan.Confidence, plan.Source, plan.ControlRef, plan.AutoApply)

			if plan.AutoApply && !*dryRun {
				// Execution engine intentionally not wired. See README.
				entry.Applied = false
				entry.Error = "auto-apply execution not yet implemented — dry-run enforced"
			}
		}

		line, _ := json.Marshal(entry)
		auditFile.Write(append(line, '\n'))
	}

	if scanTimeMs > 0 {
		fmt.Printf("[cortex] scan took %dms\n", scanTimeMs)
	}
	fmt.Printf("[cortex] audit trail written to %s\n", *auditPath)
}
