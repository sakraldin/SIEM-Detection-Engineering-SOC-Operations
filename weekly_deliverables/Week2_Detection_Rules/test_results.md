# Test Results (Week 2)

**Platform:** Wazuh 4.14.10 | **Attacker:** Kali | **Targets:** ubuntu-victim (001), ubuntu-victim2 (002)
**Date:** 14 Nov 2026 | **Times:** Dashboard time (UTC+2) unless stated

| Rule | Test type | Action performed | Expected | Actual | Result |
|---|---|---|---|---|---|
| 100010 | Positive | hydra / repeated wrong SSH passwords against victim | Alert from the 6th failure | 8 alerts, 2:32 PM to 2:35 PM | Pass |
| 100010 | Negative | 5 wrong SSH passwords in about 26 seconds (5:30:03 to 5:30:29 PM) | No alert | No new 100010 | Pass |
| 100010 | After tuning (ignore=120) | hydra, 40 wrong passwords, about 2m19s | Fewer alerts | 1 alert (5:35:41 PM) instead of 8 | Pass |
| 100011 | Positive | Successful SSH login with the time window temporarily widened to 00:00-23:59 | Alert level 7 | 2 alerts (3:01:12 PM and 3:01:52 PM) | Pass |
| 100011 | Negative | Several successful SSH logins (4:41 PM to 4:52 PM) after restoring 20:00-08:00, during business hours (UTC) | No alert | Still 2 hits only (checked 6:22 PM) | Pass |
| 100012 | Positive | SSH to victim then victim2 from Kali within 5 minutes | Alert level 12 | 2 alerts (4:46:55 PM and 4:52:57 PM) | Pass |
| 100012 | Negative | 2 SSH logins on the same host (4:45:38 PM and 4:46:42 PM) | No alert | No 100012 between them | Pass |
| 100013 | Positive | sudo adduser backdoor1 and sudo adduser fimtest on victim | Alert level 10 | 2 alerts (5:01:18 PM and 5:22:09 PM) | Pass |
| 100013 | Negative | sudo usermod -c on an existing user (about 6:17 PM) | No alert | No new 100013 (still 2 hits at 6:17:54 PM) | Pass |
| 100014 | Positive | sudo scp /etc/hostname to victim, sudo curl --version on victim2 | Alert level 10 | 2 alerts (5:05:55 PM and 5:06:33 PM) | Pass |
| 100014 | Negative | curl --version without sudo on victim (5:28 PM) | No alert | Still 2 hits | Pass (known false negative) |
| 100014 | False-positive check (before fix) | sudo sync on victim (6:25:57 PM) | No alert | Alert at 6:26:00 PM | Fail, led to tuning |
| 100014 | Negative (after fix) | sudo sync on victim (6:28:54 PM) | No alert | No new 100014 | Pass |
| 100014 | Positive (after fix) | sudo curl --version on victim (6:31:38 PM) | Alert level 10 | Alert at 6:31:40 PM | Pass |
| 100015 | Positive | sudo su - on victim | Alert level 10 | 1 alert (5:10:36 PM) | Pass |
| 100015 | Negative | sudo ls on victim | No alert | Still 1 hit | Pass |
| 100016 | Positive | sudo adduser fimtest on victim (realtime FIM) | Alert level 12 | 4 alerts, 2 for /etc/passwd and 2 for /etc/shadow (5:22:08 to 5:22:33 PM) | Pass |
| 100016 | Expected extra triggers | deluser fimtest (5:23:56 PM) and usermod -c twice (about 6:17 PM) | Alert, since passwd and shadow changed | 2 alerts at 5:23:56 PM (passwd and shadow), 2 alerts at 6:17:16 and 6:17:31 PM (passwd) | Pass (true positives) |
| 100016 | Negative | sudo touch /etc/test_fim_neg2 at 4:20:24 PM UTC (6:20 PM) | FIM event only, no 100016 | FIM rule 554 at 6:20:35 PM, no 100016 after 6:17:31 PM | Pass |

## Summary

- 7 rules, 7 positive tests passed.
- 7 of 7 rules have a passed negative test.
- 1 false positive found during testing (100014 on sudo sync) and fixed by tuning the regex.
- Other issues fixed during testing: unsupported tags in 100012 (different_agent, different_host, not_same_agent), alert flooding in 100010, FIM realtime not enabled by default.
- Known false negative: 100014 does not see transfer tools run without sudo (journald logs only sudo commands).