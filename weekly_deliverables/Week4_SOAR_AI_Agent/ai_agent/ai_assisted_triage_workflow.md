# AI-assisted triage workflow (SOC Triage Agent)

## Design
| Property | Implementation | Evidence |
|---|---|---|
| Local model | Ollama 0.40.16, `qwen3.5:4b`, CPU only (i7-6820HQ, 16 GB RAM), thinking off, JSON output | W4_01, W4_02 |
| Read-only | Indexer user `soc_agent`, role `soc_agent_ro` (read on `wazuh-alerts-4.x-*`, `soc-triage`); write returns 403 | W4_03-W4_08 |
| Network | Indexer listens on 127.0.0.1 only; agent connects through an SSH tunnel; Ollama on localhost | W4_06 |
| Untrusted input | Log content is passed as data; the system prompt forbids following instructions in it | code |
| Human in the loop | Every suggestion is accepted, overridden or rejected by the analyst; decisions are logged (`decisions.jsonl`) | W4_09, W4_10 |
| No actions | The agent cannot block, close or write anything | code |

## Workflow
1. Fetch alerts of rules 100010-100016 for a time range (read-only query).
2. Group into cases: same rule + source IP + agent, split when alerts are more than 10 minutes apart.
3. Enrich each case: asset context, rule note, related alerts (+-10 min), FIM change summary.
4. Model suggests verdict, severity, confidence, summary, evidence, actions (asked 3 times in v2.1).
5. Deterministic layer: schema validation, severity floor from the Wazuh level, output checks
   (external-IP claim, action target, evidence present in case data, time window), dismissal policy
   (false_positive only for rule 100014, level < 12, confidence >= 0.8, no check fired, runs unanimous).
6. Analyst reviews and decides. Only the analyst's decision counts.

## Results on the 14 Nov 2026 data (28 alerts, 11 cases; reference = Week 3 incident register: 10 TP, 1 FP)
| Metric | v1 | v2 | v2.1 (3 runs per case) |
|---|---|---|---|
| Verdict agreement | 10/11 | 9/11 | 10/11 |
| Attack labelled false_positive (dangerous) | 0 | 2 | 0 |
| True positives recognised | 9/10 | 8/10 | 10/10 |
| The one false positive (CASE-011) | recognised | recognised | not recognised (needs_review) |
| Severity exact match | 6/9 | 7/9 | 9/9 (3 raised by the floor; model alone 6/9) |
| Seconds per model call (mean) | 56.2 | 59.0 | 46.9 |
| Run-to-run verdict stability | not measured | not measured | 10/11 cases unanimous (32 of 33 calls true_positive) |

## Findings
1. v2 added context and got worse: the model used the time-window hint to dismiss a real login (CASE-002) and
   reasoned that an internal source cannot be a brute-force attack (CASE-009). Both were flagged by the output checks,
   but v2 did not use the checks to block a dismissal.
2. v2.1 removed the dangerous errors but the model now answers true_positive almost always, including twice on the
   known false positive. With 10 TP and 1 FP, "always true_positive" scores 10/11, so these numbers do not show that
   the agent can tell attacks from noise.
3. Verdicts were more reliable than explanations. v1 audit: 5 clean, 3 weak, 3 with a factual error. Errors persisted
   in v2.1 (internal IP called external in CASE-005; "root-level privileges" invented in CASE-004; an unrelated alert
   9 minutes later called "concurrent" in CASE-010).
4. The severity improvement comes from a deterministic rule, not from the model.
5. Speed: 47-59 s per call on CPU. Usable for batch review, not for real-time triage.

## Limits of the evaluation
- 11 cases, one day, lab-generated attacks, one false positive.
- The reference is the analyst's own Week 3 register.
- v2 and v2.1 were tuned after seeing results on the same 11 cases; their scores are in-sample.
- v1 and v2 were run once; differences of one case between versions are within run-to-run noise.

## Conclusion
A 4B local model is usable as a summariser and prioritisation aid under analyst review.
It should not close or dismiss alerts on its own; the deterministic checks and the analyst prevented the dangerous errors.
