# Measured results — lab day 2026-11-14

- Incidents: 11 total, 11 closed → **closure rate 100%**
- **MTTD mean 52.444 s** (min 0 s, max 301.5 s)
- **MTTR mean 514.211 min** (min 427.0, max 646.4)
- Alerts (custom rules 100010–100016): **28**, on **ubuntu-victim 24** and **ubuntu-victim2 4**
- Alerts with a source IP: **13**, all from **192.168.56.103**
- Severity: high / critical / medium (high largest)
- Verdicts: **10 true positive (simulated)**, **1 false positive (9.09%)**
- Escalations: **1** (INC-003)

## Tuning evidence
Brute-force MTTD went from **252 s (INC-001)** before tuning to **14 s (INC-009)** after, same attack type.
