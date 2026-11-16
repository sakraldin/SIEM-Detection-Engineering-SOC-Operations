# Field Mapping: Raw Log → Wazuh Normalized Fields

**Lab:** Wazuh 4.14.10 (192.168.56.110) | **Agent:** ubuntu-victim (ID 001, 192.168.56.111, Ubuntu 26.04.1 LTS)
**Index:** `wazuh-alerts-4.x-2026.11.07` | **Collection location:** `journald`

Legend: ✅ = value seen directly in my screenshots, 🔎 = expected from the decoder, verify in the Dashboard JSON tab.

---

## 1. How a raw log becomes a normalized alert

```
Raw log line (journald on ubuntu-victim)
        │
        ▼
Wazuh Agent (logcollector) ── forwards ──► Wazuh Manager
                                              │
                         ┌────────────────────┴────────────────────┐
                         ▼                                         ▼
                  Predecoder                                   Decoder
          (timestamp, hostname, program)            (extracts fields: user, IP, ...)
                         └────────────────────┬────────────────────┘
                                              ▼
                                     Rules engine (rule.id, level, MITRE)
                                              ▼
                                  Indexer → Dashboard (alert JSON)
```

---

## 2. Source A: SSH failed login (Rule 5710)

**Raw logs:**
```
Nov 07 05:18:10 ubuntu-victim sshd-session[4129]: Invalid user fakeuser from 127.0.0.1 port 59792
Nov 07 05:18:20 ubuntu-victim sshd-session[4129]: Failed password for invalid user fakeuser from 127.0.0.1 port 59792 ssh2
```

| Raw log element | Wazuh field | Value in my lab | Meaning | Status |
|---|---|---|---|---|
| Timestamp | `timestamp` / `@timestamp` | 2026-11-07T05:18:21.628+0000 | Event time (UTC) | ✅ |
| Hostname | `agent.name` | ubuntu-victim | Source machine | ✅ |
| Agent ID / IP | `agent.id`, `agent.ip` | 001, 192.168.56.111 | Which endpoint sent it | ✅ |
| Process name | `predecoder.program_name` | sshd-session | Program that wrote the log | ✅ |
| Username attempted | `data.srcuser` | fakeuser | Account tried by the attacker | 🔎 |
| Source IP | `data.srcip` | 127.0.0.1 | Attacker IP (localhost in this test) | ✅ |
| Source port | `data.srcport` | 59792 | Attacker port | 🔎 |
| Whole raw line | `full_log` | Failed password for invalid user fakeuser from 127.0.0.1 port 59792 ssh2 | Original log | ✅ |
| Log source | `location` | journald | Where the agent read it | ✅ |
| Decoder | `decoder.name` / `decoder.parent` | sshd / sshd | Parser used | ✅ |
| Matched rule | `rule.id` | 5710 | Detection rule | ✅ |
| Rule description | `rule.description` | sshd: Attempt to login using a non-existent user | What happened | ✅ |
| Severity | `rule.level` | 5 | Scale 0–15 | ✅ |
| Rule groups | `rule.groups` | syslog, sshd, authentication_failed, invalid_login | Categories for filtering | ✅ |
| Times fired | `rule.firedtimes` | 2 | Count since manager start | ✅ |
| MITRE technique | `rule.mitre.technique` | Password Guessing, SSH | ATT&CK technique names | ✅ |
| MITRE ID | `rule.mitre.id` | T1110.001, T1021.004 | ATT&CK IDs | ✅ |
| MITRE tactic | `rule.mitre.tactic` | Credential Access, Lateral Movement | ATT&CK tactics | ✅ |
| Compliance tags | `rule.nist_800_53`, `rule.gdpr`, `rule.gpg13` | AU.14, AC.7, AU.6 / IV_35.7.d, IV_32.2 / 7.1 | Compliance mapping | ✅ |

**Note:** the program name in the raw log is `sshd-session` (newer OpenSSH splits sessions), but the decoder is `sshd`. Wazuh still matches it correctly.

---

## 3. Source B: sudo command execution (Rule 5402)

**Raw log:**
```
Nov 07 05:18:43 ubuntu-victim sudo[4141]: victim : TTY=/dev/pts/0 ; PWD=/home/victim ; USER=root ; COMMAND=/usr/bin/touch /etc/test_fim_file
```

| Raw log element | Wazuh field | Value in my lab | Meaning | Status |
|---|---|---|---|---|
| Timestamp | `timestamp` | 2026-11-07T05:18:45.636+0000 | Event time (UTC) | ✅ |
| Hostname | `agent.name` | ubuntu-victim | Source machine | ✅ |
| Process name | `predecoder.program_name` | sudo | Program | 🔎 |
| User who ran sudo | `data.srcuser` | victim | Who executed | 🔎 |
| Target user | `data.dstuser` | root | Privilege gained | 🔎 |
| Terminal | `data.tty` | /dev/pts/0 | Session terminal | 🔎 |
| Working directory | `data.pwd` | /home/victim | Where it ran | 🔎 |
| Command | `data.command` | /usr/bin/touch /etc/test_fim_file | What was executed | 🔎 |
| Whole raw line | `full_log` | (line above) | Original log | ✅ |
| Log source | `location` | journald | Where the agent read it | ✅ |
| Decoder | `decoder.name` / `decoder.parent` | sudo / sudo | Parser used | ✅ |
| Decoder comment | `decoder.ftscomment` | First time user executed the sudo command | First-time-seen logic | ✅ |
| Matched rule | `rule.id` | 5402 | Detection rule | ✅ |
| Rule description | `rule.description` | Successful sudo to ROOT executed. | What happened | ✅ |
| Severity | `rule.level` | 3 | Low (normal admin activity) | ✅ |
| Rule groups | `rule.groups` | syslog, sudo | Categories | ✅ |
| Times fired | `rule.firedtimes` | 5 | Count since manager start | ✅ |
| MITRE technique / ID | `rule.mitre.technique`, `rule.mitre.id` | Sudo and Sudo Caching / T1548.003 | ATT&CK | ✅ |
| MITRE tactic | `rule.mitre.tactic` | Privilege Escalation, Defense Evasion | ATT&CK | ✅ |

---

## 4. Source C: repeated authentication failures (Rule 2502)

**Raw log:**
```
Nov 07 05:18:33 ubuntu-victim sshd-session[4129]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1
```

| Raw log element | Wazuh field | Value in my lab | Meaning | Status |
|---|---|---|---|---|
| Hostname | `agent.name` | ubuntu-victim | Source machine | ✅ |
| Process name | `predecoder.program_name` | sshd-session | Program | ✅ |
| Remote host | `data.srcip` | 127.0.0.1 | Source of failures (from `rhost=`) | ✅ |
| UID / EUID | `data.uid`, `data.euid` | 0, 0 | User IDs in the PAM message | ✅ |
| TTY | `data.tty` | ssh | Session type | ✅ |
| Whole raw line | `full_log` | (line above) | Original log | ✅ |
| Matched rule | `rule.id` | 2502 | Detection rule | ✅ |
| Rule description | `rule.description` | syslog: User missed the password more than one time | What happened | ✅ |
| Severity | `rule.level` | 10 | High (repeated failures) | ✅ |
| MITRE ID | `rule.mitre.id` | (check in JSON) | Likely Brute Force (T1110) | 🔎 |

---

## 5. Observations

1. **Timezone:** the Dashboard shows `07:18` while `full_log` and `timestamp` show `05:18`. The Dashboard displays my local time (UTC+2), the stored data is UTC. All correlation rules must use UTC.
2. **Severity scale:** the same SSH/sudo activity ranges from level 3 (normal) to level 10 (repeated failures). This is the basis for the alert-priority logic in Week 2.
3. **All source IPs are `127.0.0.1`:** the tests were run from the victim itself. In Week 2 attacks from Kali (192.168.56.x) will give a real `data.srcip`.
4. **MITRE mapping comes built-in** with the rules (`rule.mitre.*`), which will be reused for the MITRE coverage map in Week 4.

## 6. Common normalized fields (used across all sources)

| Normalized field | Purpose |
|---|---|
| `@timestamp` / `timestamp` | Event time |
| `agent.id`, `agent.name`, `agent.ip` | Asset identification |
| `data.srcip`, `data.srcuser`, `data.dstuser` | Who and from where |
| `rule.id`, `rule.level`, `rule.description`, `rule.groups` | Detection and priority |
| `rule.mitre.id`, `rule.mitre.tactic`, `rule.mitre.technique` | ATT&CK mapping |
| `full_log` | Evidence / original log |
| `decoder.name` | Parser used |
| `location` | Log source on the endpoint |
