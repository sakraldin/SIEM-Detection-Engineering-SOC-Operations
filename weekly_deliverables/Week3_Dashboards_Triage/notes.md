# Week 3 notes: SOC dashboard, alert triage and KPIs

Lab: Wazuh 4.14.10 (VirtualBox), activity on 2026-11-14 (UTC). Dashboard shows UTC+2.
Full report: `Week3_SIEM_Report.docx`.

## Results
| KPI | Value |
|---|---|
| Incidents total / closed | 11 / 11 (closure rate 100%) |
| MTTD (mean) | 52.444 s (252 s before tuning, 14 s after) |
| MTTR (mean) | 514.211 min (about 8.6 h), inflated by batch closure |
| Alerts (rules 100010 to 100016) | 28 (ubuntu-victim 24, ubuntu-victim2 4) |
| Top attacker | 192.168.56.103 (Kali), 13 alerts with a source IP |
| Verdicts | 10 true positive (simulated), 1 false positive |
| Escalated | 1 (INC-003) |

## Folder map
| Path | Content |
|---|---|
| screenshots/dashboard | KPI tiles, charts, assembled dashboard (W3_16 to W3_28) |
| screenshots/triage | Index, incident register, evidence, closures (W3_01 to W3_15) |
| screenshots/threat_intel | Empty this week (private IPs only) |
| kpi/ | Definitions, SLA targets, results, scripted fields |
| triage_reports/ | Incident register, workflow, INC-001, INC-003, INC-008, index mapping |
| escalation/ | Escalation matrix, INC-003 SBAR message |

## Enrichment
### Asset inventory
| Hostname | IP | Role | Agent | Criticality (assigned) |
|---|---|---|---|---|
| wazuh-server | 192.168.56.110 | SIEM manager, indexer, dashboard | n/a | Critical |
| ubuntu-victim | 192.168.56.111 | Linux server | 001 | High |
| ubuntu-victim2 | 192.168.56.113 | Linux server | 002 | High |
| admin workstation | 192.168.56.1 | Analyst and admin host | n/a | High |
| kali | 192.168.56.103 | Attacker VM | n/a | Adversary in the lab |

### Source-IP context
- 192.168.56.103: RFC1918, Kali attacker VM per inventory, source of all 13 alerts that carry a source IP.
- 192.168.56.1: RFC1918, admin workstation, origin of the authorized sudo and FIM tests.
- No public IP appears in any incident, so external lookups were not applicable. Planned for Week 4.

### MITRE ATT&CK mapping
| Rule | Detection | Tactic | Technique |
|---|---|---|---|
| 100010 | SSH brute force | Credential Access | T1110 |
| 100011 | Login outside business hours | Initial Access / Persistence | T1078 |
| 100012 | Same source IP on two hosts | Lateral Movement | T1021 |
| 100013 | New user account | Persistence | T1136.001 |
| 100014 | Data transfer tool via sudo | Exfiltration | T1048 |
| 100015 | Root shell via sudo | Privilege Escalation | T1548.003 |
| 100016 | passwd or shadow modified | Persistence | T1098 |

## Detection gaps
| ID | Finding | Evidence | Recommendation |
|---|---|---|---|
| GAP-1 | Rule 100012 correlates by source IP only; pivot through an intermediate host is not detected | INC-003 | Chain rule: login on host A then outbound SSH from A to host B |
| GAP-2 | Rule 100014 matches the tool name only (curl --version, "sudo sync" false positive) | INC-006, INC-011 | Slash anchor applied; match arguments or destination next |
| GAP-3 | FIM alerts have no who-data | INC-008, INC-010 | Enable who-data for /etc |
| GAP-4 | Brute force detection slow (252 s) | INC-001, INC-009 | Tuned to 14 s |
| GAP-5 | No case/closure state in Wazuh, MTTR not native | Whole week | Custom soc-triage index; ticketing or SOAR in production |
| GAP-6 | No rule for login followed by sudo su within 5 minutes | Week 2 backlog | Sequence rule 100017 |

## Caveats
- MTTR is inflated: incidents were triaged and closed in a batch after the test session.
- Screenshot W3_28 shows the dashboard in edit mode; replace it with a Full-screen capture of the saved dashboard if needed.
- SLA targets and asset criticality are lab-assigned proposals.

## Next (Week 4)
IOC and threat-intel enrichment, MITRE coverage map, SOAR playbook, read-only Ollama SOC triage agent, sequence rule 100017.
