# INC-001 — SSH Brute Force (rule 100010)

| Field | Value |
|---|---|
| Severity | High · MITRE T1110 (Brute Force) |
| Source | 192.168.56.103 (Kali attacker) |
| Target | ubuntu-victim (192.168.56.111, agent 001) |
| First malicious event | 2026-11-14 12:28:24 UTC |
| Detected | 12:32:36 UTC (MTTD 252 s) |
| Volume | 114 underlying events, 8 Wazuh alerts |
| Verdict | True positive — simulated attack from lab |
| Escalated | No |

## Timeline
- 12:28:24 first failed SSH authentication from 192.168.56.103.
- Failed attempts continue in a burst against the same account.
- 12:32:36 rule 100010 fires.

## Analysis
Repeated failed SSH logins from a single internal IP against one host in a short window match the brute-force pattern. The source is the Kali lab machine, so the activity is expected in this exercise; in production this would be a confirmed attack.

## Decision
Close as true positive (simulated). Detection took 252 s because the original rule threshold waited too long. The rule was tuned (INC-009): same attack detected in 14 s.

## Recommended actions (production)
Block source IP, enforce key-based SSH auth, enable fail2ban / rate limit, review any successful login from the same IP.
