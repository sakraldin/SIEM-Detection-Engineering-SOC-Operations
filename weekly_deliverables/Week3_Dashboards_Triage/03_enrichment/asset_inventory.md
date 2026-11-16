# Asset inventory (lab, internal)

| Hostname | IP | Role | Wazuh agent | Criticality (assigned) |
|---|---|---|---|---|
| wazuh-server | 192.168.56.110 | SIEM manager / indexer / dashboard | — | Critical |
| ubuntu-victim | 192.168.56.111 | Linux server (monitored) | 001 | High |
| ubuntu-victim2 | 192.168.56.113 | Linux server (monitored) | 002 | High |
| admin workstation | 192.168.56.1 | Analyst / admin host (Windows) | — | High |
| kali | 192.168.56.103 | Attacker / red-team machine | — | n/a (adversary in lab) |

Criticality values are assigned for the lab to drive severity and escalation decisions; they are not auto-discovered.
