# INC-008 — passwd/shadow modified + account creation (rule 100016)

| Field | Value |
|---|---|
| Severity | Critical · MITRE T1098 (Account Manipulation) / T1136.001 |
| Target | ubuntu-victim (agent 001) |
| Detected | 2026-11-14 15:22:08 UTC |
| Volume | 7 alerts (passwd, shadow, group changes) |
| Verdict | True positive — authorized FIM test |
| Escalated | No |

## What happened
`sudo adduser fimtest` was run on the victim from the admin session (192.168.56.1). File Integrity Monitoring flagged changes to /etc/passwd, /etc/shadow and /etc/group. The files were restored to their baseline hashes at ~15:23:56 UTC.

## Analysis
Changes to credential files are high-impact in any environment, so the critical level is right. Here the change is authorized and part of the test plan, hence no escalation.

## Gap found
FIM alerts do not say **who** made the change (no who-data). In production the analyst would have to correlate with auth/sudo logs manually. Recommendation: enable `whodata` on /etc (see 06_findings, GAP-3).
