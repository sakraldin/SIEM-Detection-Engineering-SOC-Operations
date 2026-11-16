# SOC Operations Dashboard

Dashboard name: `W3 - SOC Operations Dashboard` (time range stored: 2026-11-14 12:00 → 20:00, dashboard shows UTC+2).

## Visualizations
| # | Name | Type | Index pattern | Config |
|---|---|---|---|---|
| 1 | W3 - Total Incidents | Metric | soc-triage | Count, label "Total incidents" |
| 2 | W3 - Closed Incidents | Metric | soc-triage | Count, query `status:closed` |
| 3 | W3 - MTTD | Metric | soc-triage | Average of `mttd_seconds` |
| 4 | W3 - MTTR | Metric | soc-triage | Average of `mttr_minutes` |
| 5 | W3 - Alert Volume by Rule | Area | wazuh-alerts-* | Query rule.id 100010–100016; X: date histogram (hour); split: terms rule.id |
| 6 | W3 - Top Attackers | Data table | wazuh-alerts-* | Terms `data.srcip`, size 10 |
| 7 | W3 - Top Targets | Data table | wazuh-alerts-* | Terms `agent.name`, size 10 |
| 8 | W3 - Incidents by Severity | Pie | soc-triage | Terms `severity` |
| 9 | W3 - Verdicts | Pie | soc-triage | Terms `verdict` |

Alert query used on wazuh-alerts-*:
`rule.id:(100010 or 100011 or 100012 or 100013 or 100014 or 100015 or 100016)`

Closure rate = Closed / Total = 11 / 11 = 100%.

## Notes
- `W3_01_dashboard.png` currently shows the edit-mode capture; replace it with a Full-screen capture of the saved dashboard.
- Dashboard displays UTC+2 (browser), the manager/index stores UTC.
