# Lab Configuration (end of Week 2)

**Date:** 14 Nov 2026 | **Platform:** Wazuh 4.14.10 on VirtualBox 7.2.4

## 1. Machines

| VM name in VirtualBox | Role | Host-only IP | Wazuh agent | Resources | Snapshot |
|---|---|---|---|---|---|
| Wazuh v4.14.10 OVA | SIEM (Manager, Indexer, Dashboard) | 192.168.56.110 | Agent 000 (built-in) | 4 GB RAM, 2 CPU, 50 GB disk | Week2_Rules_Final |
| Ubuntu-Victim | Monitored endpoint (user: victim) | 192.168.56.111 | Agent 001 (ubuntu-victim) | 2 GB RAM, 1 CPU, 25 GB disk | Week2_Rules_Final |
| Ubuntu-Victim2 | Second monitored endpoint (user: victim2), added for lateral movement tests | 192.168.56.113 | Agent 002 (ubuntu-victim2) | (verify: planned 1 GB RAM, 1 CPU, 20 GB disk) | Week2_Rules_Final |
| attacker | Kali attacker (hydra, ssh) | (verify: Host-only 192.168.56.x) | none | (verify) | week 2 |

## 2. Network design

- Adapter 1: Host-only (isolated lab traffic, 192.168.56.0/24).
- Adapter 2: NAT (internet for updates only).
- All attack traffic stays inside the Host-only network.

## 3. Time zones

- Manager and endpoints run in UTC.
- The Dashboard displays the browser time zone (UTC+2).
- The time condition of rule 100011 is evaluated on the manager clock (UTC).

## 4. Configuration changes made in Week 2

| Where | File | Change | Reason | Backup |
|---|---|---|---|---|
| wazuh-server | /var/ossec/etc/rules/local_rules.xml | Added rules 100010 to 100016; later added ignore="120" to 100010 and the "/" in the 100014 regex | Detection rules and tuning | local_rules.xml.bak (before ignore), local_rules.xml.bak2 (before regex fix) |
| ubuntu-victim | /var/ossec/etc/ossec.conf, line 114 | Added check_all="yes" realtime="yes" to the directories line for /etc,/usr/bin,/usr/sbin | Realtime FIM for rule 100016 | ossec.conf.bak |
| ubuntu-victim2 | Wazuh agent installed (Agent 002) | Registered to the manager 192.168.56.110 | Second host for rule 100012 | n/a |

Not changed in Week 2: /var/ossec/etc/ossec.conf on the manager (default), default Wazuh rules and decoders.

## 5. Active agents

| ID | Name | IP | Status |
|---|---|---|---|
| 000 | wazuh-server | 127.0.0.1 | active (built-in) |
| 001 | ubuntu-victim | 192.168.56.111 | active |
| 002 | ubuntu-victim2 | 192.168.56.113 | active |

## 6. Attack and test tooling (on Kali)

- ssh with the option NumberOfPasswordPrompts=1 for single failed attempts.
- hydra against ssh://192.168.56.111 with a wordlist of 40 wrong passwords (wrong1 to wrong40), one task at a time (-t 1).

## 7. Test accounts and files

| Item | Where | Status |
|---|---|---|
| fimtest user | ubuntu-victim | Removed (deluser --remove-home) |
| backdoor1 user | ubuntu-victim | (verify: removed with deluser --remove-home) |
| testuser1 user | ubuntu-victim | (verify: removed, created in Week 1) |
| /etc/test_fim_neg2 | ubuntu-victim | Removed |
| /tmp/wl.txt | Kali | Wordlist for hydra, can be kept |

## 8. Snapshots

| Snapshot | VMs | Taken | Description |
|---|---|---|---|
| Week1_Clean_Baseline | Wazuh, Ubuntu-Victim | Week 1 | Wazuh configured, agent connected, passwords changed |
| Week2_Rules_Final | Wazuh, Ubuntu-Victim, Ubuntu-Victim2 | 14 Nov 2026, 6:38 PM | 7 custom rules (100010-100016), FIM realtime on victim, ready for Week 3 |

## 9. Security notes

- Passwords are kept in a private file outside the project, not in notes, configs or screenshots.
- Start order for the lab: wazuh-server first (wait 3 to 5 minutes for the Dashboard), then the endpoints.