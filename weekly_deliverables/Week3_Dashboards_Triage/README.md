# Week 3 — SOC Dashboard, Alert Triage & KPIs

Lab: Wazuh 4.14.10 (VirtualBox) · Period of activity: 2026-11-14 (UTC)

## Results at a glance
| KPI | Value |
|---|---|
| Total incidents | 11 |
| Closed incidents / Closure rate | 11 / 100% |
| MTTD (mean) | 52.444 s (252 s before tuning → 14 s after) |
| MTTR (mean) | 514.211 min (≈ 8.6 h) — inflated, closed in batch after the lab session |
| Top attacker | 192.168.56.103 (Kali) — 13 alerts with a source IP |
| Top target | ubuntu-victim — 24 of 28 alerts |
| Verdicts | 10 true positive (simulated) / 1 false positive |
| Escalated | 1 (INC-003, lateral movement) |

## Folder index
| Folder | Content |
|---|---|
| 01_dashboard | Dashboard screenshots, scripted fields, visualization list |
| 02_triage | Incident register + triage reports (INC-001, INC-003, INC-008), soc-triage index mapping and data |
| 03_enrichment | Asset inventory, threat-intel / context notes, MITRE mapping |
| 04_kpi_and_sla | KPI definitions, SLA targets, measured results |
| 05_escalation | Escalation matrix, INC-003 SBAR message |
| 06_findings | Detection gaps and recommendations |

Report: `Week3_SIEM_Report.docx` (built after this folder is final).

## Screenshot index
See `01_dashboard/screenshots/` (W3_01 … W3_06b). Triage evidence screenshots go in `02_triage/screenshots/` (W3_07 onward).
