# Week 4 notes: SOAR, threat intel, MITRE coverage, AI triage agent

## Folder map
- `mitre/mitre_coverage_map.md`
- `soar/PB-01_ssh_bruteforce_playbook.md`
- `threat_intel/ioc_enrichment.md`
- `ai_agent/ai_assisted_triage_workflow.md`, `code/` (v1, v2, v2.1), `runs/` (v1, v2, v2.1 outputs), `evaluation/`
- `screenshots/` W4_01-W4_24 (annotated); `screenshots/original/` (unannotated)
- `Week4_SIEM_Report.docx` (22 pages)

## Environment changes this week
- wazuh-server: 2 GB swap file added (manager failed to start with 3.8 GB RAM and no swap); active-response block appended to ossec.conf.
- Indexer: role `soc_agent_ro`, user `soc_agent`.
- Windows host: Ollama 0.40.16, Python 3.14, `C:\soc-agent`.

## Rule 100011 check (16 Nov)
- Rule on disk: `<time>20:00 - 08:00</time>`; manager clock is UTC.
- Test: successful SSH login from Kali at 08:07 UTC raised no alert. The two alerts in the previous 24 h (03:52 and 05:36 UTC) are inside the window. The time condition works.
- INC-002 (14 Nov 13:01 UTC) is not explained by the current configuration. Week 2 used a temporary test window, and `local_rules.xml` was last modified 14 Nov 16:27 UTC; a test window active at that time is likely but not proven.
- The rule also fires on admin logins from 192.168.56.1 at night and on wazuh-server itself.

## Open items
- White-list 192.168.56.1 in Active Response; exclude the admin source in rule 100011.
- Project Documentation package (proposal, plan, requirements, diagrams, test plan, README, user manual).
