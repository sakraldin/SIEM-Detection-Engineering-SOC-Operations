# Detection gaps and recommendations

| ID | Finding | Evidence | Recommendation |
|---|---|---|---|
| GAP-1 | Rule 100012 correlates by source IP only; a pivot via an intermediate host (.111 → .113) is not detected | INC-003 | Add a sequence/chain rule: login on host A followed by outbound SSH from A to host B within N minutes |
| GAP-2 | Rule 100014 matches the tool name only; `curl --version` triggers it (low fidelity). It also produced a false positive on `sync` (contains "nc") | INC-011 | Anchor the command with `/` (already applied); match on arguments or destination, not name alone |
| GAP-3 | FIM alerts have no who-data (who changed /etc/passwd) | INC-008, INC-010 | Enable `whodata` for /etc in syscheck so alerts carry user and process |
| GAP-4 | Brute-force detection was slow (252 s) | INC-001 | Rule tuned; INC-009 detected in 14 s. Keep the threshold under review |
| GAP-5 | MTTR cannot be measured in Wazuh (no case/closure state) | Whole week | Custom soc-triage index used; in production use a ticketing/SOAR integration (Week 4) |
| GAP-6 | Sequence "login then sudo su within 5 min" not detected | Week 2 backlog | Rule 100017 (deferred) |

## Tuning log
- 100010 threshold lowered → MTTD 252 s → 14 s.
- 100014 regex anchored with `/` → no alert on later `sudo sync`; `curl --version` validated as post-fix detection.
