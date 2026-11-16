# Incident register (index: soc-triage) — times in UTC, 2026-11-14

| ID | Rule | Name | Sev | MITRE | Detected | Closed | MTTD (s) | MTTR (min) | Verdict | Escalated |
|---|---|---|---|---|---|---|---|---|---|---|
| INC-001 | 100010 | SSH Brute Force | high | T1110 | 12:32:36 | 23:19:00 | 252.0 | 646.4 | TP (simulated) | no |
| INC-002 | 100011 | Time-window login | medium | T1078 | 13:01:12 | 23:31:00 | 0 | 629.8 | TP (simulated) | no |
| INC-003 | 100012 | Same-IP login to 2 hosts (lateral movement) | critical | T1021 | 14:46:55 | 23:25:00 | 301.5 | 518.1 | TP (simulated) | **yes** |
| INC-004 | 100012 | Same-IP login to 2 hosts | critical | T1021 | 14:52:57 | 23:31:00 | 9.4 | 518.0 | TP (simulated) | no |
| INC-005 | 100013 | New account created | high | T1136.001 | 15:01:18 | 23:31:00 | 0 | 509.7 | TP (simulated) | no |
| INC-006 | 100014 | Data transfer tool via sudo | high | T1048 | 15:05:55 | 23:33:00 | 0 | 507.1 | TP (simulated) | no |
| INC-007 | 100015 | Privilege escalation via sudo shell | high | T1548.003 | 15:10:36 | 23:33:00 | 0 | 502.4 | TP (simulated) | no |
| INC-008 | 100016 | passwd/shadow modified + account creation | critical | T1098 | 15:22:08 | 23:29:00 | 0 | 486.9 | TP (authorized FIM test) | no |
| INC-009 | 100010 | SSH Brute Force (after tuning) | high | T1110 | 15:35:41 | 23:31:00 | 14.0 | 475.3 | TP (simulated) | no |
| INC-010 | 100016 | passwd/shadow modified | critical | T1098 | 16:17:16 | 23:33:00 | 0 | 435.7 | TP (authorized FIM test) | no |
| INC-011 | 100014 | Data transfer tool via sudo | high | T1048 | 16:26:00 | 23:33:00 | 0 | 427.0 | **FP** (`sync` matched "nc") | no |

Mean MTTD = 52.444 s · Mean MTTR = 514.211 min · Closure rate = 100%.
MTTD = 0 for single-event rules (attack start = detection).
