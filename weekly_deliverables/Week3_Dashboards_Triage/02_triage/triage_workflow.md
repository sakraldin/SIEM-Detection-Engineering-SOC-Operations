# Triage workflow used (applied to every incident)

1. **Receive** — alert fires in Wazuh (rule id, level, agent, timestamp).
2. **Validate** — pull the underlying events (Discover / Dev Tools) around the alert; confirm the alert is real and not a rule artifact.
3. **Scope** — source IP, target host(s), account(s), time window, number of events.
4. **Enrich** — asset criticality and role, source-IP context, MITRE technique (see 03_enrichment).
5. **Classify** — verdict: true positive / false positive / benign; severity.
6. **Decide** — close with note, tune rule, or escalate (see 05_escalation).
7. **Record** — write incident into `soc-triage` (attack_started, detected_at, closed_at, verdict, triage_note) so MTTD/MTTR are computed from data.
8. **Improve** — feed false positives and detection gaps back into rules (06_findings).
