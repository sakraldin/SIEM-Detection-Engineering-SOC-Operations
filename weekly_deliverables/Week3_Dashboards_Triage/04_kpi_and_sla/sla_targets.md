# Proposed SLA targets (to be agreed with the SOC manager)

| Severity | Acknowledge | MTTD target | Resolve (MTTR) target | Escalation |
|---|---|---|---|---|
| Critical | ≤ 5 min | ≤ 5 min | ≤ 1 h | Immediate to SOC lead / IR |
| High | ≤ 15 min | ≤ 10 min | ≤ 4 h | If TP and impact on a critical asset |
| Medium | ≤ 1 h | ≤ 30 min | ≤ 8 h | If repeated or correlated |
| Low | ≤ 4 h | ≤ 1 h | ≤ 24 h | Not required |

## Comparison with lab results
| KPI | Result | Target | Status |
|---|---|---|---|
| MTTD (mean) | 52.4 s | ≤ 5 min | Met (INC-001 252 s and INC-003 301 s are at/over the critical-high boundary; fixed for brute force by tuning) |
| MTTR (mean) | 514.2 min | ≤ 1–4 h | Not met — artifact of batch closure; fix by closing incidents as they are handled |
| Closure rate | 100% | 100% | Met |
