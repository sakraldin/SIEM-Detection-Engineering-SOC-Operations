# Tuning Notes (Week 2)

**Platform:** Wazuh 4.14.10 | **Date:** 14 Nov 2026
**Method:** each rule was tested with a positive case (must alert) and a negative case (must not alert). False positives and false negatives were then recorded with the decision taken.

## 1. Tuning changes applied

| Rule | Problem found | Change | Evidence | Trade-off |
|---|---|---|---|---|
| 100010 | Alert flooding: one brute-force run gave 8 alerts, one every 30 seconds after the 6th failure | Added ignore="120" | Same type of attack (hydra, 40 wrong passwords) gave 1 alert instead of 8 | ignore is per rule, so a second attacker inside the 120 second window may be suppressed |
| 100012 | Wazuh counts frequency per agent only, so cross-host correlation never fired | Added global_frequency, same_source_ip and different_location (different_agent, different_host and not_same_agent were rejected or deprecated in 4.14.10) | Fired at 4:46:55 PM and 4:52:57 PM after SSH to victim then victim2 | global_frequency works at manager level, not cluster level |
| 100014 | False positive: sudo sync matched because the regex had no "/" before the tool name (the suffix "nc" of "sync" matched) | Regex now requires "/" before the tool name (backup: local_rules.xml.bak2) | Before: sudo sync gave an alert at 6:26:00 PM. After: sudo sync gave no alert (6:28:54 PM) and sudo curl --version still alerted (6:31:40 PM) | Tools called without a path are not matched |

New regex for 100014: COMMAND=\S*/(scp|rsync|sftp|curl|wget|ncat|nc)(\s|$)

## 2. Negative tests (false-positive checks)

| Rule | Negative test | Expected | Result |
|---|---|---|---|
| 100010 | 5 failed SSH passwords in about 26 seconds | No alert (threshold is 6) | Pass |
| 100011 | Successful SSH logins during business hours (UTC) after restoring the 20:00-08:00 window | No alert | Pass: still 2 hits only (from the widened-window test) |
| 100012 | 2 successful SSH logins on the same host (4:45:38 PM and 4:46:42 PM) | No alert | Pass |
| 100013 | sudo usermod -c on an existing user | No alert | Pass: no new 100013 |
| 100014 | sudo sync | No alert | Fail before tuning, Pass after tuning |
| 100014 | curl --version without sudo | No alert | Pass, but this is also a known false negative (see section 3) |
| 100015 | sudo ls | No alert | Pass |
| 100016 | sudo touch /etc/test_fim_neg2 (file in /etc, not passwd or shadow) | FIM event only | Pass: FIM rule 554 fired, 100016 did not |

## 3. Known false negatives (detection gaps)

| Rule | Gap | Reason | Proposed improvement |
|---|---|---|---|
| 100010 | Distributed or slow brute force (many IPs, or fewer than 6 attempts per 120 seconds) | Threshold is per source IP | Longer timeframe rule, or a rule per target user |
| 100011 | Logins by an attacker during business hours, and off-hours logins by services or cron | Time-only logic, no per-user baseline | Add a user baseline and IP reputation |
| 100012 | Lateral movement over protocols other than SSH (SMB, RDP, WinRM) | Only rule 5715 is correlated | Add Windows events (4624 logon types 3 and 10) when a Windows source is onboarded |
| 100014 | Transfer tools run without sudo, or other methods (python, bash redirection) | journald logs only sudo commands | Enable auditd execve logging, or use network and firewall logs |
| 100015 | Root shell by other means (sudo -s, su from an existing root session, SUID binaries) | The regex covers a short list of shells | Extend the regex and add auditd |
| 100016 | Changes to other critical files (sudoers, sshd_config, authorized_keys) | The rule matches only passwd and shadow | Add more paths to the field regex and to the syscheck configuration |

## 4. Known false positives (expected benign triggers)

| Rule | Benign trigger | Mitigation |
|---|---|---|
| 100011 | Legitimate on-call logins at night | Allowlist by user or source IP |
| 100012 | Admin using one workstation to manage several servers | Allowlist of admin IPs (proposed, not tested: a CDB list or a negated srcip match) |
| 100013 | Legitimate account provisioning | Correlate with change tickets |
| 100014 | Admin uses sudo curl or scp for maintenance | Allowlist by user and destination |
| 100015 | Admin uses sudo -i | Allowlist known admins, or lower the level and escalate only with other signals |
| 100016 | Admin changes a password or user information (observed: deluser at 5:23:56 PM and usermod at 6:17 PM triggered it) | Correlate with a ticket or expected user |

## 5. Environment constraints

- The lab has 2 Linux endpoints only, with no Windows, network or cloud source, so detections rely on endpoint logs.
- The time window in 100011 is evaluated on the manager clock, which is UTC in the lab.
- All thresholds were chosen for lab testing and must be re-baselined on real traffic before production.

## 6. Next review

- Re-test all rules after any Wazuh upgrade, because the options accepted by the rules engine changed between versions.
- Review thresholds and allowlists monthly using alert volume per rule from the dashboard (Week 3).