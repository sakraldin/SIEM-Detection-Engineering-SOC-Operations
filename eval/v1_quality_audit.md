# Agent v1 - summary and evidence quality audit (manual review of 11 cases)

Rating: CLEAN = every statement supported by the case data; WEAK = verdict right, reasoning thin;
ERROR = at least one statement false or unsupported.

| Case | Rule | Verdict ok | Quality | Finding | v2 countermeasure |
|---|---|---|---|---|---|
| CASE-001 | 100010 | yes | CLEAN | Evidence quoted from sample_logs. | - |
| CASE-002 | 100011 | yes | ERROR | Claims "outside business hours" without checking the time. Alert time 13:01 UTC is outside the rule window 20:00-08:00 (rule description and alert disagree). | `time_check` field + output check flag |
| CASE-003 | 100012 | yes | WEAK | 3 of 5 evidence items are counters/timestamps; says "the victim host twice" (rule means 2 different hosts); severity high vs critical in register. | rule_note, related_alerts, evidence rule, severity floor |
| CASE-004 | 100013 | yes | CLEAN | Account name and UID quoted from log. | - |
| CASE-005 | 100014 | yes | ERROR | Calls internal 192.168.56.111 an "external IP/destination"; recommends blocking that internal host; says "sensitive system files (hostname)". Cause: src_ip "-" + "no asset record" read as external. | local-event context text, prompt rule on RFC1918, output checks (external claim, action target) |
| CASE-006 | 100015 | yes | CLEAN | Evidence quoted from log fields. | - |
| CASE-007 | 100016 | yes | CLEAN | File sizes and inode quoted correctly. Cannot know the test was authorized (no who-data, GAP-3). | fim_changes summary |
| CASE-008 | 100013 | no (needs_review vs TP) | WEAK | Infers "legitimate test account" from the name fimtest only; did not link the same-second FIM alert on /etc/passwd. | related_alerts (+1 s FIM alert), "do not guess intent from names" |
| CASE-009 | 100010 | yes | ERROR | Reads rule_alerts=1 as "a single failed attempt"; one alert already stands for 6 events. Lowered severity to medium. | rule_note for frequency rules, counter renamed rule_alerts_in_case, severity floor |
| CASE-010 | 100016 | yes | WEAK | Evidence cut by the 300-char sample ("New md5sum" with no value); did not notice the second change reverted the file size (1844 -> 1832). Severity high vs critical in register. | fim_changes with size direction, severity floor |
| CASE-011 | 100014 | yes | CLEAN | Judged the real commands (sync, curl --version). | - |

Totals: CLEAN 5, WEAK 3, ERROR 3. Two of the ten correct verdicts (CASE-005, CASE-009) rest on flawed reasoning,
so verdict accuracy alone overstates reliability.

## Other observations
- Recommendation inflation: 6 of 11 cases recommend isolating or blocking, some with thin evidence.
- Run-to-run variation: in an earlier 3-case run the evidence of CASE-003 changed (metadata vs real log lines) while the verdict stayed the same.
- The guardrail raised no note in the run; schema retries were not logged (added in v2: `attempts`, `schema_errors`).
- Evaluation caveats: n = 11, single run, lab-generated attacks (10 TP, 1 FP), reference = the analyst's own Week 3 register, agent saw only the 7 custom rules.
