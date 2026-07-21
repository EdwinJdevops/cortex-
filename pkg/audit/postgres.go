// Package audit persists Cortex decisions to Postgres. Falls back to
// nothing gracefully if DATABASE_URL is unset — JSONL local logging
// (in cmd/cortex/main.go) always runs regardless, so an audit trail
// exists even without a DB configured.
package audit

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	"github.com/EdwinJdevops/cortex/pkg/reasoner"
	"github.com/EdwinJdevops/cortex/pkg/scanner"
)

type Store struct {
	db *sql.DB
}

// NewStore connects to Postgres using DATABASE_URL. Caller must Close().
func NewStore(databaseURL string) (*Store, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// RecordScan inserts a scan run and returns its UUID for FK linkage.
func (s *Store) RecordScan(ctx context.Context, namespace string, result *scanner.ScanResult) (string, error) {
	var scanID string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO scans (namespace, scan_time_ms, violation_count)
		VALUES ($1, $2, $3)
		RETURNING id
	`, namespace, result.ScanTimeMs, len(result.Violations)).Scan(&scanID)
	if err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}
	return scanID, nil
}

// RecordViolationAndDecision inserts a violation and its remediation
// decision atomically. Returns the violation UUID.
func (s *Store) RecordViolationAndDecision(ctx context.Context, scanID string, v scanner.Violation, plan *reasoner.RemediationPlan, applied bool, applyErr string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var violationID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO violations (scan_id, resource_type, resource_id, policy_name, severity, description)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, scanID, v.ResourceType, v.ResourceID, v.PolicyName, v.Severity, v.Description).Scan(&violationID)
	if err != nil {
		return "", fmt.Errorf("insert violation: %w", err)
	}

	if plan != nil {
		var errMsg sql.NullString
		if applyErr != "" {
			errMsg = sql.NullString{String: applyErr, Valid: true}
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO remediation_decisions
				(violation_id, action, confidence, source, control_ref, reasoning, auto_apply, applied, error_message)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, violationID, plan.Action, plan.Confidence, plan.Source, plan.ControlRef, plan.Reasoning, plan.AutoApply, applied, errMsg)
		if err != nil {
			return "", fmt.Errorf("insert decision: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit tx: %w", err)
	}
	return violationID, nil
}

// DeterministicRatio queries the reporting view — the headline metric
// proving Cortex isn't just an LLM wrapper.
func (s *Store) DeterministicRatio(ctx context.Context) (ruleEngine, llm int, pct float64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT rule_engine_decisions, llm_decisions, deterministic_pct FROM deterministic_ratio`).
		Scan(&ruleEngine, &llm, &pct)
	return
}
