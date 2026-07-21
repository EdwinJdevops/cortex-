# Cortex Demo Script (3:00)

## [0:00–0:20] Hook — the problem, no fluff
"Every AI DevOps tool right now does the same thing: find a problem, ask an
LLM what to do, run whatever it says. That's fine until the LLM confidently
hallucinates a fix that breaks production. Cortex doesn't do that."

## [0:20–0:50] Architecture, on screen (show README diagram)
"Cortex scans a Kubernetes cluster — sub-100ms, no LLM in the hot path.
Every violation first checks against a deterministic rule table mapped to
real CIS Kubernetes Benchmark controls. Privileged containers, missing
resource limits, exposed secrets — these are known patterns. Zero tokens,
zero hallucination risk, resolved in under a millisecond."

## [0:50–1:30] Live terminal — the deterministic path
```bash
./cortex --namespace demo --dry-run=true
```
Show output:
```
[cortex] scanning namespace=demo
[cortex] scan complete in 43ms — 3 violations found
[cortex] pod/nginx-x7f -> action="set securityContext.privileged=false" confidence=0.99 source=rule_engine auto_apply=true
[cortex] pod/api-2k9 -> action="apply ResourceQuota..." confidence=0.97 source=rule_engine auto_apply=true
```
"Zero API calls so far. Two real, documented security violations, resolved
deterministically."

## [1:30–2:10] The escalation path — where Qwen comes in
"Now here's a violation with no matching rule — something novel."
```
[cortex] pod/weird-mount-4x -> action="review volume mount permissions" confidence=0.71 source=qwen_llm auto_apply=false
```
"Qwen reasons about it. But look at the confidence — 0.71. Below our 0.95
threshold. auto_apply is forced false. The model doesn't get to bypass the
safety gate just because it sounds confident."

## [2:10–2:40] The audit trail — the differentiator
```bash
cat cortex-audit.jsonl | jq .
```
"Every single decision — rule-based or LLM-based — is written here before
anything is ever considered for execution. This is what turns 'AI made a
decision' into 'here's exactly why, with what confidence, traceable to what
control.'"

## [2:40–3:00] Close
"Cortex isn't pretending an LLM should have unsupervised write access to
your cluster. It's a deterministic engine first, with LLM reasoning as a
bounded, audited fallback — because that's how this actually needs to work
in production, not in a demo."

---

## Recording notes
- Use `asciinema` or plain terminal recording — no fake UI, no slides with
  buzzwords. The terminal output IS the proof.
- Keep the rule-table code visible on screen for 2-3 seconds during
  [0:20-0:50] — judges skim code, don't just narrate over a blank terminal.
- Do not claim "fully autonomous" anywhere in the video — the honest
  "dry-run, human-gated" framing is the credibility play against generic
  submissions.
