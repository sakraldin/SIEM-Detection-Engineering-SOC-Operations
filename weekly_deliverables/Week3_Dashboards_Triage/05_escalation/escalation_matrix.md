# Escalation matrix

| Condition | Level | Who | When | Channel |
|---|---|---|---|---|
| Critical alert, true positive, production asset | L3 | SOC lead + Incident Response | Immediately (≤ 5 min) | Phone + ticket |
| Lateral movement or privilege escalation confirmed | L3 | SOC lead + IR | Immediately | Phone + ticket |
| High alert, true positive on critical asset | L2 | Senior analyst | ≤ 15 min | Ticket + chat |
| Medium, repeated or correlated with other alerts | L2 | Senior analyst | ≤ 1 h | Ticket |
| False positive / authorized activity | L1 | Closed by analyst | — | Note in soc-triage + rule tuning |

## Escalate when any of these is true
1. Activity is confirmed malicious and touches an asset rated High/Critical.
2. Evidence of lateral movement, persistence, or credential compromise.
3. Scope is unclear or growing.
4. The analyst cannot decide within the SLA.

## Applied in this lab
Only INC-003 met the criteria (critical severity, two hosts, lateral movement) and was escalated. INC-008/INC-010 (critical FIM) were not escalated because they were authorized tests.
