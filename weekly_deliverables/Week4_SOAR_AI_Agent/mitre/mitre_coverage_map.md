# MITRE ATT&CK coverage map (custom rules 100010-100016)

| Rule | Level | Technique | Tactic(s) of the technique | Tested in lab | Detection quality |
|---|---|---|---|---|---|
| 100010 SSH brute force | 10 | T1110 Brute Force | Credential Access | INC-001, INC-009, SOAR test 16 Nov | Good after tuning (MTTD 252 s -> 14 s) |
| 100011 Login in time window | 7 | T1078 Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion | INC-002 | Time window verified 16 Nov; also fires on admin night-time logins |
| 100012 Same IP to 2 hosts | 12 | T1021 Remote Services | Lateral Movement | INC-003, INC-004 | Misses a pivot through an intermediate host (GAP-1) |
| 100013 New local account | 10 | T1136.001 Create Account: Local Account | Persistence | INC-005, INC-008 | Good; no actor information |
| 100014 Transfer tool via sudo | 10 | T1048 Exfiltration Over Alternative Protocol | Exfiltration | INC-006, INC-011 (FP) | Low fidelity: matches the tool name only (GAP-2) |
| 100015 Root shell via sudo | 10 | T1548.003 Sudo and Sudo Caching | Privilege Escalation, Defense Evasion | INC-007 | Good |
| 100016 passwd/shadow changed | 12 | T1098 Account Manipulation | Persistence, Privilege Escalation | INC-008, INC-010 | No who-data (GAP-3) |

## Coverage by tactic (Enterprise, 14 tactics)

| Tactic | Covered by | Status |
|---|---|---|
| Reconnaissance | - | Not covered |
| Resource Development | - | Not covered (outside host telemetry) |
| Initial Access | 100011 (T1078) | Partial |
| Execution | - | Not covered |
| Persistence | 100013, 100016, 100011 | Covered |
| Privilege Escalation | 100015, 100016 | Covered |
| Defense Evasion | 100015, 100011 (shared techniques) | Nominal only |
| Credential Access | 100010 | Covered |
| Discovery | - | Not covered |
| Lateral Movement | 100012 | Partial (GAP-1) |
| Collection | - | Not covered |
| Command and Control | - | Not covered |
| Exfiltration | 100014 | Partial (GAP-2) |
| Impact | - | Not covered |

7 techniques (5 techniques + 2 sub-techniques counted as listed) across 7 of 14 tactics.
A tactic is listed when one rule maps to a technique that belongs to it; each rule was tested only
for the behaviour in its own row. Linux SSH/sudo/FIM telemetry only: no network, process or web telemetry.

## Priority gaps
1. Execution and Discovery (e.g. T1059 command interpreter, T1082/T1033 discovery commands): needs auditd or command logging.
2. Command and Control: needs network telemetry (Suricata or firewall logs).
3. Sequence rule 100017 (login then sudo su within 5 min) is still pseudocode (GAP-6).
