# Data Source Inventory

**Organization model:** medium-size company (about 200–500 users, mixed Windows/Linux, hybrid cloud)
**Lab SIEM:** Wazuh 4.14.10 on VirtualBox (Manager 192.168.56.110)

Status legend: ✅ Implemented in lab | ⏳ Planned for a later week | 📄 Documented only (not feasible in the lab)

---

## 1. Inventory by category

| # | Category | Source | Log types / events | Collection method | Key fields | Priority | Lab status |
|---|---|---|---|---|---|---|---|
| 1 | Endpoint | Linux servers (Ubuntu) | auth.log, syslog, sudo, sshd, journald | Wazuh agent | `data.srcip`, `data.srcuser`, `rule.id` | High | ✅ ubuntu-victim (ID 001) |
| 2 | Endpoint | Wazuh Manager host | Wazuh internal logs, system logs | Built-in agent (ID 000) | `agent.name`, `rule.id` | Medium | ✅ |
| 3 | Endpoint | Windows servers / workstations | Security Events 4624, 4625, 4688, 4697, 7045; Sysmon | Wazuh agent (+ Sysmon) | `data.win.eventdata.*` | High | ⏳ Week 2 if RAM allows |
| 4 | Endpoint | File integrity (critical paths) | File create/modify/delete | Wazuh FIM (syscheck) | `syscheck.path`, `syscheck.event` | Medium | ⏳ Week 2 |
| 5 | Network | Firewall | Allow/deny, NAT, VPN logs | Syslog forwarding to Manager (UDP/TCP 514) | `data.srcip`, `data.dstip`, `data.action` | High | 📄 Documented |
| 6 | Network | IDS/IPS (Suricata) | Alerts, flows, DNS | Agent reading `eve.json` | `data.alert.signature`, `data.src_ip` | High | ⏳ Optional |
| 7 | Network | DNS / Proxy | Queries, URLs, categories | Syslog or agent | `data.url`, `data.query` | Medium | 📄 Documented |
| 8 | Identity | Active Directory / Domain Controller | 4624/4625 logons, 4720 user created, 4728/4732 group changes, 4768/4769 Kerberos | Wazuh agent on DC | `data.win.eventdata.targetUserName` | High | 📄 Documented |
| 9 | Identity | VPN / SSO / MFA provider | Login success/failure, MFA events | Syslog / API | `data.srcuser`, `data.srcip` | High | 📄 Documented |
| 10 | Cloud | AWS CloudTrail / Azure Activity | API calls, IAM changes, console logins | Wazuh cloud modules (S3 / Event Hub) | `data.aws.*`, `data.azure.*` | Medium | 📄 Documented |
| 11 | Application | Web server (Apache / Nginx) | Access and error logs | Agent `localfile` | `data.id`, `data.url`, `data.protocol` | Medium | ⏳ Optional |
| 12 | Application | Database (MySQL / PostgreSQL) | Auth failures, privileged queries | Agent `localfile` | `data.srcuser` | Medium | 📄 Documented |
| 13 | Application | Email gateway | Phishing detections, attachments | Syslog / API | `data.sender`, `data.subject` | High | 📄 Documented (needed for Week 4 phishing playbook) |

---

## 2. Lab implementation (what is running now)

| Component | Role | IP | Notes |
|---|---|---|---|
| wazuh-server | SIEM (Manager + Indexer + Dashboard) | 192.168.56.110 (Host-only), 10.0.3.15 (NAT) | 4 GB RAM, 2 CPU |
| ubuntu-victim | Monitored endpoint (Agent 001) | 192.168.56.111 (Host-only) | Ubuntu 26.04.1 LTS, 2 GB RAM |
| Kali_linux | Attacker (used in Week 2) | Host-only network | Started only when needed |

**Network design:** Adapter 1 = Host-only (lab traffic, isolated), Adapter 2 = NAT (internet for updates).

**Verified log flow:** journald on ubuntu-victim → Wazuh agent → Manager (192.168.56.110) → Indexer → Dashboard. Proven by 68 events in the first test (rules 5710, 5402, 2502, 5901, 5902, 5501/5502, 5503).

---

## 3. Events verified from the lab source

| Activity performed | Resulting rule | Level | Description |
|---|---|---|---|
| Wrong sudo password | 2502 | 10 | syslog: User missed the password more than one time |
| Successful sudo | 5402 | 3 | Successful sudo to ROOT executed |
| `adduser testuser1` | 5902 / 5901 / 5555 | 8 / 8 / 3 | New user / new group added, password changed |
| SSH with non-existent user | 5710 | 5 | sshd: Attempt to login using a non-existent user |
| PAM failure | 5503 | 5 | PAM: User login failed |

---

## 4. Collection method summary

| Method | Used for | In lab |
|---|---|---|
| Wazuh agent | Endpoints (Linux/Windows) | ✅ |
| Syslog forwarding | Firewalls, network devices | 📄 |
| Log file monitoring (`localfile`) | Web/DB application logs | ⏳ |
| API / cloud module | AWS, Azure, SaaS | 📄 |

## 5. Gaps and risks

1. No Windows source yet: lateral movement and persistence rules (Week 2) are richer with Windows events.
2. No network source: no firewall/IDS visibility, so network-based exfiltration detection is limited to endpoint logs.
3. Identity and cloud are documented only because the lab has no AD or cloud tenant.
4. Time sync: all sources must use NTP and UTC, otherwise correlation breaks.
