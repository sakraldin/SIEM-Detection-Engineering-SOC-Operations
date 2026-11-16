# Detection Use Cases and Rule Logic (Week 2)

**Platform:** Wazuh 4.14.10 | **Rules file:** /var/ossec/etc/rules/local_rules.xml (final version: local_rules_v2_final.xml)
**Endpoints:** ubuntu-victim (Agent 001), ubuntu-victim2 (Agent 002) | **Attacker:** Kali
**Date:** 14 Nov 2026

## Summary

| ID | Use case | Logic type | Level | MITRE |
|---|---|---|---|---|
| 100010 | SSH Brute Force | Threshold | 10 | T1110 |
| 100011 | Suspicious Login (off-hours) | Behavioral (time-based) | 7 | T1078 |
| 100012 | Lateral Movement | Correlation across hosts | 12 | T1021 |
| 100013 | Persistence: new account | Event-based | 10 | T1136.001 |
| 100014 | Data Exfiltration tools | Event plus pattern match | 10 | T1048 |
| 100015 | Privilege Escalation: root shell | Event plus pattern match | 10 | T1548.003 |
| 100016 | FIM on /etc/passwd and /etc/shadow | Integrity monitoring | 12 | T1098 |

Detailed test evidence is in test_results.md and tuning decisions are in tuning_notes.md.

## 100010 SSH Brute Force

- **Pseudocode:** IF 6 events of "sshd: authentication failed" (rule 5760) come from the same source IP within 120 seconds THEN alert, and ignore further alerts from this rule for 120 seconds.
- **Rule options:** if_matched_sid 5760, frequency 6, timeframe 120, same_source_ip, ignore 120.
- **Tuning:** ignore="120" was added to stop alert flooding (8 alerts per attack before, 1 after).
- **Limits:** a distributed attack (many IPs, few attempts each) is not detected. The ignore option works per rule, so a second attacker inside the 120 second window may be suppressed.

## 100011 Suspicious Login

- **Pseudocode:** IF a successful SSH login (rule 5715) happens AND the event time is between 20:00 and 08:00 THEN alert.
- **Rule options:** if_sid 5715, time 20:00 - 08:00.
- **Limits:** the time window is evaluated on the manager clock (UTC in the lab), so it must be adapted to the organization's time zone. There is no per-user baseline.

## 100012 Lateral Movement

- **Pseudocode:** IF the same source IP has a successful SSH login on 2 different hosts within 300 seconds THEN alert.
- **Rule options:** if_matched_sid 5715, frequency 2, timeframe 300, global_frequency, same_source_ip, different_location.
- **Note:** by default Wazuh counts frequency per agent only. global_frequency makes it count events from all agents (manager level, not cluster level). The options different_agent, different_host and not_same_agent are not usable in version 4.14.10.
- **Limits:** only SSH is correlated. Legitimate admins jumping between hosts will trigger it (needs an allowlist in production).

## 100013 Persistence: new account

- **Pseudocode:** IF a new user is added to the system (rule 5902) THEN alert.
- **Rule options:** if_sid 5902.
- **Limits:** legitimate user provisioning also triggers it, so it should be correlated with change tickets.

## 100014 Data Exfiltration tools

- **Pseudocode:** IF a successful sudo (rule 5402) runs a command whose executable is scp, rsync, sftp, curl, wget, ncat or nc THEN alert.
- **Rule options:** if_sid 5402, pcre2 regex on the COMMAND= part of the log.
- **Regex:** COMMAND=\S*/(scp|rsync|sftp|curl|wget|ncat|nc)(\s|$)
- **Tuning:** the "/" before the tool name prevents commands like sync from matching (sudo sync caused a false positive before the fix).
- **Limits:** only commands run with sudo are logged in journald, so transfers by normal users are not detected (known false negative). There is no volume-based detection.

## 100015 Privilege Escalation

- **Pseudocode:** IF a successful sudo (rule 5402) runs su, bash, sh, zsh or dash THEN alert.
- **Rule options:** if_sid 5402, pcre2 regex on the COMMAND= part of the log.
- **Regex:** COMMAND=\S*/(su|bash|sh|zsh|dash)(\s|$)
- **Limits:** admins who legitimately use sudo -i will trigger it.

## 100016 FIM on critical files

- **Pseudocode:** IF syscheck reports an integrity change (rule 550) on /etc/passwd or /etc/shadow THEN alert.
- **Rule options:** if_sid 550, field "file" matching ^/etc/passwd$ or ^/etc/shadow$.
- **Agent configuration:** realtime="yes" and check_all="yes" on the /etc directories line in the agent ossec.conf (ubuntu-victim).
- **Limits:** realtime monitoring only covers the configured paths. Password changes by admins also trigger it. Other critical files (sudoers, sshd_config, authorized_keys) are not covered yet.

## Rule logic (pseudocode)

Notation: E is the incoming event, `now` is the manager clock (UTC), and every rule fires at most once per matching event.

### 100010: SSH brute force (T1110, level 10)

    ON event E where E.rule_id == 5760            # sshd: authentication failed
        key    = E.srcip
        window = events with rule_id 5760, same srcip (same agent), last 120 s
        IF count(window) >= 6 AND rule 100010 not suppressed:
            RAISE alert(level=10, srcip=key)
            SUPPRESS rule 100010 for 120 s        # ignore="120", one alert per attack

### 100011: login outside business hours (T1078, level 7)

    ON event E where E.rule_id == 5715            # sshd: authentication success
        t = now.time (UTC)
        IF t >= 20:00 OR t < 08:00:
            RAISE alert(level=7, user=E.dstuser, srcip=E.srcip)

### 100012: lateral movement (T1021, level 12)

    ON event E where E.rule_id == 5715
        window = events with rule_id 5715 from ALL agents, last 300 s   # global_frequency
        same   = window where srcip == E.srcip                          # same_source_ip
        IF count(same) >= 2 AND distinct(same.agent) >= 2:              # different_location
            RAISE alert(level=12, srcip=E.srcip, hosts=distinct(same.agent))

### 100013: new user account (T1136.001, level 10)

    ON event E where E.rule_id == 5902            # new user added
        RAISE alert(level=10, user=E.dstuser, host=E.agent)

### 100014: data exfiltration tooling (T1048, level 10)

    ON event E where E.rule_id == 5402            # sudo executed a command
        IF E.full_log MATCHES  COMMAND=\S*/(scp|rsync|sftp|curl|wget|ncat|nc)(\s|$):
            RAISE alert(level=10, tool=match, user=E.srcuser, host=E.agent)
        # the "/" before the tool name avoids matching "sync" as "nc"

### 100015: privilege escalation (T1548.003, level 10)

    ON event E where E.rule_id == 5402
        IF E.full_log MATCHES  COMMAND=\S*/(su|bash|sh|zsh|dash)(\s|$):
            RAISE alert(level=10, user=E.srcuser, host=E.agent)

### 100016: critical file modified (T1098, level 12)

    ON event E where E.rule_id == 550             # syscheck: integrity checksum changed
        IF E.file IN ("/etc/passwd", "/etc/shadow"):
            RAISE alert(level=12, file=E.file, host=E.agent)
        # needs realtime="yes" on the monitored directory, otherwise the event arrives late

### Planned: login followed by root shell (sequence, not implemented)

    ON event E1 where E1.rule_id == 5715
        START timer 300 s for key (E1.agent, E1.dstuser)
    ON event E2 where E2.rule_id == 5402 AND E2 matches root-shell regex
        IF timer exists for (E2.agent, E2.srcuser):
            RAISE alert(level=12)                 # login then sudo su within 5 minutes