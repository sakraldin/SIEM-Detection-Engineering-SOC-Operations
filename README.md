# SIEM Detection Engineering, Alert Triage & SOC Operations

DEPI graduation project: a mini SOC lab on Wazuh 4.14.10 with custom detections, incident triage and KPIs,
an automated containment playbook, a threat-intelligence test and a read-only AI triage agent.

All attacks are simulated inside an isolated VirtualBox lab. Nothing here is meant for production use.

## Repository layout

| Path | Content |
|---|---|
| `rules/` | Custom Wazuh rules 100010-100016 (`local_rules.xml`, see `rules/README.md`) |
| `config/` | Active Response block, `soc-triage` index mapping, scripted fields |
| `agent/` | SOC Triage Agent v1, v2, v2.1 and their run outputs |
| `eval/` | Evaluation script and results |
| `docs/` | Coverage map, playbook, workflow, incident register |
| `evidence/` | Annotated screenshots per week |
| `weekly_deliverables/` | Week 1-4 reports, configurations, rules, and screenshots |
| `Final_Report/` | Final report, project documentation, presentation, diagrams, and weekly reports |
| `password.txt` | Passwords for protected project files |

## System requirements

- Host: 16 GB RAM, VirtualBox, host-only network 192.168.56.0/24
- wazuh-server VM: Wazuh 4.14.10 all-in-one, 4 GB RAM and a 2 GB swap file
- Two Ubuntu Server VMs with Wazuh agents; one Kali Linux VM
- Analyst host: Python 3.10+ with `requests`, Ollama with `qwen3.5:4b` (about 3.5 GB RAM while running)

## Installation

1. **Rules** (on wazuh-server):

       sudo cp rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
       sudo /var/ossec/bin/wazuh-analysisd -t
       sudo systemctl restart wazuh-manager

2. **Active Response** (on wazuh-server): back up `/var/ossec/etc/ossec.conf`, append
   `config/active_response.xml`, restart `wazuh-manager`.
3. **Incident index** (Dashboard > Indexer management > Dev Tools): create `soc-triage` with
   `config/soc_triage_index_mapping.json`; add the scripted fields in `config/scripted_fields.md`
   to the `soc-triage` index pattern (time field `detected_at`).
4. **Read-only user for the agent** (Dev Tools):

       PUT _plugins/_security/api/roles/soc_agent_ro
       { "cluster_permissions": ["cluster_composite_ops_ro"],
         "index_permissions": [{ "index_patterns": ["wazuh-alerts-4.x-*", "soc-triage"], "allowed_actions": ["read"] }] }

       PUT _plugins/_security/api/internalusers/soc_agent
       { "password": "<choose a password>" }

       PUT _plugins/_security/api/rolesmapping/soc_agent_ro
       { "users": ["soc_agent"] }

5. **Model** (analyst host):

       ollama pull qwen3.5:4b
       pip install requests

## Configuration

Constants at the top of `agent/soc_triage_agent_v21.py`: `INDEXER`, `OLLAMA`, `MODEL`, `USER`,
`GAP_MINUTES`, `DISMISS_ALLOWED`, and the asset tables `ASSETS` / `AGENTS`.
The password is asked at run time and never stored.

## Execution

    # 1. tunnel to the indexer (it listens on 127.0.0.1 only); keep this window open
    ssh -N -L 9200:127.0.0.1:9200 wazuh-user@192.168.56.110

    # 2. run the agent with analyst review
    python agent/soc_triage_agent_v21.py --hours 24 --repeat 3

    # fixed time range (UTC), suggestions only
    python agent/soc_triage_agent_v21.py --since "2026-11-14 12:00" --until "2026-11-14 20:00" --no-review

Review keys: `a` accept, `o` override, `r` reject, `s` skip. Outputs go to `agent_output_v21/`.

Evaluate a run against the incident register:

    python eval/compare.py v1=agent/runs/v1_triage.json v2=agent/runs/v2_triage.json v21=agent/runs/v21_triage.json

## Results (lab, 14-16 November 2026)

| Item | Result |
|---|---|
| Incidents | 11 triaged and closed: 10 true positives (simulated), 1 false positive |
| MTTD | 52.4 s mean; brute force 252 s before tuning, 14 s after |
| Containment | Source blocked 35 ms after the alert, released after 600 s (one test) |
| ATT&CK | 7 techniques across 7 of 14 tactics |
| Agent verdict agreement | v1 10/11, v2 9/11 (2 attacks dismissed), v2.1 10/11 (0 dismissed) |

## Limitations

- Small lab, simulated attacks, one day of incident data.
- The agent evaluation uses 11 cases with one false positive and cannot rank the versions.
  The agent is an assistant; it must not close or dismiss alerts on its own.
- TLS verification to the indexer is disabled for the lab's self-signed certificate.
- Open gaps are listed in the Final SOC Operations Report, section 9.

## Team

| No. | Name | Role |
|---|---|---|
| 1 |  |  |
| 2 |  |  |
| 3 |  |  |
| 4 |  |  |
| 5 |  |  |
| 6 |  |  |

Supervisor:
