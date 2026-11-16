# Custom Rules (Week 2)

**Platform:** Wazuh 4.14.10 | **Date:** 14 Nov 2026

## Files

| File | Purpose |
|---|---|
| local_rules_v2_final.xml | Final rules file, deployed on the manager |
| local_rules_v1_tested.xml | Version used for most tests, before the 100014 regex fix |
| agent_syscheck_snippet.xml | Agent-side FIM change required by rule 100016 (ubuntu-victim, ossec.conf line 114) |

The only difference between v1 and v2 is the regex of rule 100014 (v2 requires "/" before the tool name).

## Rules

| ID | Use case | Level | MITRE |
|---|---|---|---|
| 100010 | SSH Brute Force (6 failures / 120 s, ignore 120 s) | 10 | T1110 |
| 100011 | Suspicious Login (outside 20:00-08:00) | 7 | T1078 |
| 100012 | Lateral Movement (same IP, 2 hosts, 300 s) | 12 | T1021 |
| 100013 | Persistence: new user account | 10 | T1136.001 |
| 100014 | Data Exfiltration: file transfer tool with sudo | 10 | T1048 |
| 100015 | Privilege Escalation: root shell with sudo | 10 | T1548.003 |
| 100016 | FIM on /etc/passwd and /etc/shadow | 12 | T1098 |

Rule 100001 is the default example rule that ships in the file.

## Deploy

On the manager (wazuh-server):

1. Back up the current file:
   sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
2. Copy local_rules_v2_final.xml to /var/ossec/etc/rules/local_rules.xml
3. Validate (no WARNING or ERROR expected, only the INFO line about memory):
   sudo /var/ossec/bin/wazuh-analysisd -t
4. Restart the manager:
   sudo systemctl restart wazuh-manager
   sudo systemctl status wazuh-manager

On the agent (ubuntu-victim), for rule 100016:

1. Back up ossec.conf, then apply agent_syscheck_snippet.xml to line 114.
2. sudo systemctl restart wazuh-agent

## Backups created on the manager during the work

| File | Taken before |
|---|---|
| local_rules.xml.bak | Adding ignore="120" to rule 100010 |
| local_rules.xml.bak2 | Fixing the regex of rule 100014 |
| ossec.conf.bak (on ubuntu-victim) | Enabling realtime FIM on line 114 |

## Notes

- Options different_agent, different_host and not_same_agent are not usable in 4.14.10. Rule 100012 uses global_frequency, same_source_ip and different_location instead.
- The time window of rule 100011 is evaluated on the manager clock (UTC in the lab).
- Re-test all rules after a Wazuh upgrade.

See ../detection_use_cases.md, ../tuning_notes.md and ../test_results.md for logic, tuning decisions and test evidence.