# KPI definitions

| KPI | Definition | Formula | Source fields |
|---|---|---|---|
| MTTD (Mean Time To Detect) | Time from the first malicious event to the alert | mean(detected_at − attack_started) | soc-triage `attack_started`, `detected_at` |
| MTTR (Mean Time To Respond/Resolve) | Time from alert to incident closure | mean(closed_at − detected_at) | `detected_at`, `closed_at` |
| Alert volume | Count of custom-rule alerts per period | count(rule.id 100010–100016) | wazuh-alerts-* |
| Closure rate | Share of incidents closed | closed / total × 100 | `status` |
| Top attackers | Source IPs by alert count | terms(data.srcip) | wazuh-alerts-* |
| Top targets | Hosts by alert count | terms(agent.name) | wazuh-alerts-* |

## How attack_started is determined
From the first real underlying event found in the logs (not from the alert). For single-event rules (FIM, new account, sudo) the attack start equals the detection time, so MTTD = 0 for those incidents.

## Important caveats
- **MTTR is inflated (514 min ≈ 8.6 h).** Incidents were triaged and closed in a batch after the lab session. It reflects the lab workflow, not analyst speed. In production, MTTR is measured with a ticketing workflow and compared with the SLA.
- **MTTD is dominated by two multi-event incidents** (INC-001 252 s, INC-003 301 s). The other incidents are 0–14 s.
- Dashboard shows UTC+2; stored values are UTC.
