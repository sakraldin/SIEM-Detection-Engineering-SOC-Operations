# MITRE ATT&CK mapping

| Rule | Detection | Tactic | Technique |
|---|---|---|---|
| 100010 | SSH brute force | Credential Access | T1110 Brute Force |
| 100011 | Login in unusual time window | Initial Access / Persistence | T1078 Valid Accounts |
| 100012 | Same source IP logs into 2 hosts | Lateral Movement | T1021 Remote Services |
| 100013 | New account created | Persistence | T1136.001 Create Account: Local |
| 100014 | Data-transfer tool run via sudo | Exfiltration | T1048 Exfiltration Over Alternative Protocol |
| 100015 | su / shell via sudo | Privilege Escalation | T1548.003 Sudo and Sudo Caching |
| 100016 | /etc/passwd or /etc/shadow modified (FIM) | Persistence | T1098 Account Manipulation |
