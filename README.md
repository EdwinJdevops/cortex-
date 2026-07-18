# Cortex

**Deterministic-first infrastructure remediation. LLM reasoning only when rules can't decide.**

[![Go Report Card](https://goreportcard.com/badge/github.com/EdwinJdevops/cortex)](https://goreportcard.com/report/github.com/EdwinJdevops/cortex)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The problem with AI infra tools

Most "AI DevOps" tools send every finding to an LLM and hope it says something reasonable. That's fine for a demo. It's not fine when the output can touch a running cluster — LLMs hallucinate confidently, and confidence is not correctness.

Cortex inverts that. **Known violation patterns are resolved by a deterministic rule engine — zero tokens, zero hallucination risk, sub-millisecond decision.** Only violations that don't match a known pattern escalate to Qwen for reasoning, and even then, the model's output is treated as a *proposal*, not an action:

- Every plan is logged to an append-only audit trail before anything is considered
- `auto_apply` is hard-gated: forced `false` unless confidence ≥ 0.95 **and** the rule engine (not the LLM) already trusts this pattern
- Execution is dry-run by default — Cortex will tell you exactly what it would do, and log it, before it's ever allowed to do it

## Architecture

```
                    ┌──────────────┐
   K8s cluster ───► │   Scanner    │  subprocess exec, <100ms
                    │ (Warden CLI) │  no LLM call in the hot path
                    └──────┬───────┘
                           │ violations[]
                    ┌──────▼───────┐
                    │   Reasoner   │
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
      known pattern?               unknown pattern
              │                         │
     ┌────────▼────────┐       ┌────────▼────────┐
     │  Rule Engine     │       │   Qwen LLM      │
     │  0 tokens        │       │  reasoning +    │
     │  0.97–1.0 conf.  │       │  proposed action│
     └────────┬─────────┘       └────────┬────────┘
              │                          │
              └────────────┬─────────────┘
                            │
                   ┌────────▼─────────┐
                   │  Safety Gate      │
                   │  conf<0.95 → deny │
                   │  auto_apply       │
                   └────────┬──────────┘
                            │
                   ┌────────▼──────────┐
                   │ Append-only audit │
                   │  trail (JSONL)    │
                   └───────────────────┘
```

## Why this matters for judging

- **Not an AI wrapper**: the LLM is one branch of a decision tree, not the whole system. Remove Qwen entirely and Cortex still detects and reports the majority of real-world violations correctly.
- **Auditable**: every decision — rule-based or LLM-based — is logged with its reasoning and confidence before any action is even considered.
- **Honest about limits**: auto-patch execution is intentionally *not wired* in this version. A hackathon demo that claims to autonomously patch production clusters and doesn't show its safety rails is a liability, not a feature. Cortex shows its work instead.

## Quick start

```bash
go build -o cortex ./cmd/cortex
export QWEN_API_KEY=your_key
./cortex --namespace default --dry-run=true
cat cortex-audit.jsonl
```

## Status

Early build. Scanner + reasoner + audit trail are functional. Execution engine (the "apply" half of remediation) is deliberately unimplemented pending real-world testing against non-production clusters.

## License

MIT.
