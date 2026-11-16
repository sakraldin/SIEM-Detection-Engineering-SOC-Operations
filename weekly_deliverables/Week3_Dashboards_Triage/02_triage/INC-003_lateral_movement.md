# INC-003 — Lateral movement (rule 100012) — ESCALATED

| Field | Value |
|---|---|
| Severity | Critical · MITRE T1021 (Remote Services) |
| Source | 192.168.56.103 (Kali) |
| Targets | ubuntu-victim (.111) and ubuntu-victim2 (.113, agent 002) |
| First event | 2026-11-14 14:41:54 UTC (initial login) |
| Detected | 14:46:55 UTC (MTTD ≈ 301 s) |
| Verdict | True positive — simulated |
| Escalated | Yes |

## Analysis
The same source IP authenticated successfully to two different hosts within the correlation window. Rule 100012 correlates on the source IP, so it matches this pattern. A successful login to a second server after access to the first is the classic indicator of lateral movement, which is why severity is critical.

## Detection gap found
When the attacker pivots through an intermediate host (.111 → .113), the source IP seen by the second host is the intermediate host, not the original attacker. Rule 100012 does not link those two events (see 06_findings, GAP-1).

## Escalation
Sent to the SOC lead/IR using the SBAR format — see `05_escalation/INC-003_sbar_message.md`.

## Recommended actions (production)
Isolate both hosts, reset credentials used, review authentication logs on both, hunt for the same source across the environment.
