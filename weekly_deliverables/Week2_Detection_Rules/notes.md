## Step 12: Pipeline Health Check
- Date: 7 Nov 2026
- Goal: Confirm alerts still reach the Dashboard after password change
- Filebeat output test: talk to server... OK
- New event seen in Dashboard: Yes (129 hits total, rules 5710/5503/2502)
- Result: Pipeline healthy
- Screenshot names: W2_01, W2_02
- Problems & how I solved them: None

## Step 13: Kali Attacker Setup
- Date: 7 Nov 2026
- Goal: Prepare attacker VM on the isolated Host-only network
- VM renamed: Kali_linux -> attacker
- Attacker IP (Host-only): 192.168.56.103
- Ping to Wazuh/Ubuntu: 0% packet loss
- Hydra: /usr/bin/hydra, rockyou.txt.gz available
- Snapshot: Week2_Start
- Screenshot names: W2_03 to W2_06
- Problems & how I solved them: eth0 (Host-only) got no DHCP lease at first boot; fixed with a persistent NetworkManager connection (nmcli)

## Step 14: SSH Brute Force Attack (Hydra)
- Date: 7 Nov 2026
- Goal: Launch a real brute force attack and observe Wazuh detection
- Attack: hydra -l victim -P small_pass.txt (200 passwords + real password) ssh://192.168.56.111 -t 4
- Result: Hydra stopped early (too many connection errors) due to sshd MaxStartups limiting concurrent unauthenticated connections
- Detection: Built-in rule "sshd: brute force trying to get access" fired with data.srcip = 192.168.56.103 (real attacker IP)
- Dashboard: 433 total events, 319 auth failures, 9 auth successes (unrelated prior logins, not from this attack)
- Screenshot names: W2_07 to W2_12
- Problems & how I solved them: Hydra errored out due to SSH rate limiting; documented as an existing organic defense

## Step 14 (continued): Built-in Wazuh rules observed during the attack
- Date: 7 Nov 2026
- Rules fired:
  - 5503: PAM: User login failed (level 5, single-event, fires on each failure)
  - 5763: sshd: brute force trying to get access (level unknown, fires on repeated failures, MITRE T1110 Brute Force)
  - 5710: sshd: Attempt to login using a non-existent user (level 5)
  - 2502: syslog: User missed the password more than one time (level 10)
- Source IP confirmed real: 192.168.56.103 (attacker VM)
- Screenshot names: W2_11, W2_12, W2_13 (rule 5763 JSON)
- Problems & how I solved them: Needed Add Filter (rule.description is) instead of free-text search in DQL to locate specific rules

## Step 15: Custom Brute Force Rule
- Date: 14 Nov 2026
- Goal: Write a custom threshold-based correlation rule
- Rule ID: 100010, level 10
- Logic: if_matched_sid 5760 (sshd Failed password) + same_source_ip, frequency=6, timeframe=120
- Base rule found: 5760 "sshd: authentication failed." fires on each "Failed password" line
- MITRE: T1110 (Brute Force)
- Issue found: first attempt used if_sid with frequency/timeframe -> error "Missing if_matched on rule 100010"
- Fix: changed to if_matched_sid (required when combining with frequency/timeframe)
- Result: wazuh-manager restarted successfully, rule active
- Screenshot names: W2_15_local_rules_xml, W2_16 (final file), W2_17_manager_restart

## Step 16: Custom Rule - Final JSON Confirmation
- Date: 14 Nov 2026
- Rule: 100010, level 10, frequency 6, timeframe 120 (confirmed in JSON)
- MITRE: T1110 / Brute Force / Credential Access (confirmed)
- Source IP: 192.168.56.103 (confirmed in full_log)
- firedtimes: 8
- Status: Rule fully validated against a real attack. Deliverable "custom correlation rule" complete.
- Screenshot name: W2_21_final_rule_json_confirmed.png


## Step 17: Suspicious Login Rule (Outside Business Hours)
- Date: 14 Nov 2026
- Rule: 100011, level 7
- Logic: if_sid 5715 (sshd authentication success) + <time> window check
- Base rule found: 5715 "sshd: authentication success." (MITRE T1078 Valid Accounts, T1021 Remote Services)
- Test method: temporarily widened <time> to 00:00-23:59 to trigger immediately, since actual test time (UTC) was inside business hours
- Result: Rule 100011 fired twice at level 7 with correct description during the test window
- Final config: <time> restored to 20:00 - 08:00 (real business-hours logic)
- Screenshot names: W2_22 to W2_24
- Problems & how I solved them: None; testing method (temporary wide time window) documented for reproducibility

## Step 18 (completed): Suspicious Login Rule - Restored to production logic
- Date: 14 Nov 2026
- Change: <time> reverted from 00:00-23:59 (test) back to 20:00-08:00 (real business-hours window)
- wazuh-manager restarted: active (running) since 13:03:37 UTC
- Screenshot name: W2_24_manager_restart_final.png
- Status: Rule 100011 complete and in its final production state

## Step 19-20 (completed): Lateral Movement Rule 100012
- Date: 14 Nov 2026
- Final rule: level 12, if_matched_sid 5715 + global_frequency + same_source_ip + different_location, frequency 2 / timeframe 300
- MITRE: T1021 Remote Services
- Issues found and fixed:
  1. <different_agent> and <different_host> invalid in Wazuh 4.14.10
  2. <not_same_agent> deprecated (warning from analysisd -t), option ignored
  3. Root cause: by default frequency counts only events from the same agent; fixed with <global_frequency />
  4. First attack test did not trigger (manager restart was likely missing after the edit); second test after restart succeeded
- Test: SSH from Kali to ubuntu-victim (4:46:42 PM) then ubuntu-victim2 within 5 minutes
- Result: Rule 100012 fired at level 12 (4:46:55 PM) with correct description
-- Positive tests: rule 100012 fired twice (4:46:55 PM and 4:52:57 PM), both after SSH from Kali to ubuntu-victim then ubuntu-victim2 within 5 minutes
- Negative test: two successful SSH logins on ubuntu-victim only (4:45:38 PM and 4:46:42 PM, rule 5715) did not trigger 100012, confirming different_location separates hosts
- Note: the event that triggers a correlation rule is stored as that rule's alert (100012), not as 5715
- Screenshot names: W2_33_lateral_100012_hits.png, W2_34_5715_events.png

## Step 21: Persistence Rule (New User Account)
- Date: 14 Nov 2026
- Rule: 100013, level 10, if_sid 5902 (new user added), MITRE T1136.001 Create Account: Local Account
- Test: sudo adduser backdoor1 on ubuntu-victim
- Result: Rule 100013 fired at level 10 (5:01 PM) with correct description
- Cleanup: sudo deluser --remove-home backdoor1
- Screenshot names: W2_35 to W2_37
## Step 22: Data Exfiltration Rule (File Transfer Tool via sudo)
- Date: 14 Nov 2026
- Rule: 100014, level 10, if_sid 5402 + pcre2 regex on COMMAND= (scp|rsync|sftp|curl|wget|ncat|nc), MITRE T1048
- Tests on ubuntu-victim2: sudo scp /etc/hostname to ubuntu-victim (5:05:55 PM), sudo curl --version (5:06:33 PM)
- Result: Rule 100014 fired twice at level 10 with correct description
- Known limitation: detects only tools run with sudo; non-sudo transfers are not logged in journald (needs auditd or network monitoring, see Gaps)
- Screenshot names: W2_38 to W2_40

## Step 23: Privilege Escalation Rule (Root Shell via sudo)
- Date: 14 Nov 2026
- Rule: 100015, level 10, if_sid 5402 + pcre2 regex on COMMAND= (su|bash|sh|zsh|dash), MITRE T1548.003
- Positive test: sudo su - on ubuntu-victim, rule 100015 fired at 5:10:36 PM (level 10)
- Negative test confirmed: sudo ls (about 5:12 PM) did not trigger 100015; search at 5:13 PM still shows 1 hit (5:10:36 PM)
- Screenshot name: W2_44_privesc_negative_test.png

## Step 24: FIM Rule for Critical Files (/etc/passwd, /etc/shadow)
- Date: 14 Nov 2026
- Config (ubuntu-victim, ossec.conf line 114): <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories> (backup: ossec.conf.bak), wazuh-agent restarted
- Rule: 100016, level 12, if_sid 550 + field "file" matches ^/etc/passwd$ | ^/etc/shadow$, MITRE T1098
- Test: sudo adduser fimtest on ubuntu-victim
- Result: Rule 100016 fired 4 times at level 12 (2 for /etc/passwd, 2 for /etc/shadow) at 5:22 PM; realtime FIM confirmed (this resolves the Week 1 note that FIM events were not seen)
- Cleanup: deluser --remove-home fimtest
- Screenshot names: W2_45 to W2_48

## Step 25: Negative tests (tuning evidence)
- Date: 14 Nov 2026
- Rule 100014: curl --version without sudo on ubuntu-victim did not trigger the rule (still 2 hits from earlier sudo tests). Confirms known false negative: tools run without sudo are not logged in journald.
- Rule 100010: 5 failed SSH passwords from Kali in about 26 seconds (5:30:03 PM to 5:30:29 PM, rule 5760 x5) did not trigger 100010 (threshold is 6). Latest 100010 alert remains the old test run.
- Rule 100012: two logins on the same host did not trigger (see Step 19-20).
- Rule 100015: sudo ls did not trigger (see Step 23).
- Screenshot names: W2_49_100014_negative.png, W2_50_5760_five_failures.png, W2_51_100010_no_new_alert.png

## Step 26: Tuning Rule 100010 (alert flooding)
- Date: 14 Nov 2026
- Problem: one brute-force run (about 3.5 minutes) produced 8 alerts of rule 100010 (one every ~30 s after the 6th failure)
- Change: added ignore="120" to the rule (backup: local_rules.xml.bak)
- Test: hydra, 40 wrong passwords, 1 task, about 2m19s, against ubuntu-victim from Kali
- Result: 1 alert (5:35:41 PM) instead of 8
- Trade-off: ignore is per rule, so a second attacker inside the 120 s window may be suppressed
- Screenshot names: W2_52_hydra_run.png, W2_53_100010_after_tuning.png

## Step 27: Test results completed
- Date: 14 Nov 2026
- Added negative tests for 100011 (business-hours logins did not fire), 100013 (usermod -c did not fire) and 100016 (touch /etc/test_fim_neg2 gave FIM 554 only)
- Note: 100016 also fired on deluser (5:23:56 PM) and usermod (6:17 PM), expected since /etc/passwd and /etc/shadow changed
- Cleanup: removed /etc/test_fim_neg2
- Files: detection_use_cases.md, tuning_notes.md, test_results.md
- Screenshot names: W2_54 to W2_60

## Step 28: Tuning Rule 100014 (false positive on sudo sync)
- Date: 14 Nov 2026
- Problem: regex without "/" matched "sync" (suffix "nc"); sudo sync triggered 100014 at 6:26:00 PM
- Fix: regex now requires "/" before the tool name (backup: local_rules.xml.bak2)
- Verification: sudo sync produced no alert (6:28:54 PM); sudo curl --version produced an alert (6:31:40 PM)
- Screenshot names: W2_61 to W2_63