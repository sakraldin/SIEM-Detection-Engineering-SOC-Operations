# PB-01 SSH brute force: containment playbook

| Field | Value |
|---|---|
| Trigger | Rule 100010 (level 10, T1110): 6 failed SSH passwords from one source IP within 120 s |
| Automated action | Wazuh Active Response `firewall-drop` on the agent that raised the alert (`location: local`), timeout 600 s |
| Reversible | Yes: the iptables rule is removed automatically after 10 minutes |
| Owner | Tier-1 analyst; escalation to Tier-2 per Week 3 escalation matrix |

## Flow
1. **Detect (automatic)**: rule 100010 fires.
2. **Contain (automatic)**: `firewall-drop` adds `DROP all -- <srcip>` to INPUT on the targeted host; rule 651 is logged.
3. **Triage (analyst, within the 10-minute block)**: confirm the source IP context, check for a successful login from the same IP (rule 5715 / 100011 / 100012) before or after the failures, check the targeted account.
4. **Decide (analyst)**:
   - Successful login found -> treat as compromise: escalate (SBAR), reset the account password, review sudo and FIM alerts on the host. Longer block or host isolation needs Tier-2 approval.
   - No successful login, source is a known admin mistake -> close as benign true positive, no further action.
   - No successful login, source unknown or repeated -> request a permanent block from the firewall owner.
5. **Recover (automatic)**: rule 652 logs the unblock after 600 s. A repeat attack triggers a new block.
6. **Document**: record the incident in `soc-triage` (detected_at, closed_at, verdict).

## Automation boundary
| Action | Mode |
|---|---|
| Temporary block of the source IP on the attacked host (10 min) | Automatic |
| Permanent block, block on other hosts, host isolation | Analyst request + Tier-2 approval |
| Account disable / password reset | Analyst, manual |
| AI agent suggestions (verdict, summary) | Advisory only, never triggers an action |

## Test evidence (16 Nov 2026, UTC, server clock)
| Time | Event | Evidence |
|---|---|---|
| before | INPUT chain empty on ubuntu-victim | W4_14 |
| 05:38:31-05:38:44 | Failed passwords for `victim` from 192.168.56.103 (hydra, 6 tries completed) | W4_15, W4_17 |
| 05:38:45.289 | Alert 100010 | W4_19 |
| 05:38:45.324 | Alert 651 Host Blocked (35 ms after the alert, about 14 s after the first logged failure) | W4_16, W4_19 |
| during block | `ssh victim@192.168.56.111` from Kali hangs; hydra reports connection errors | W4_15 |
| 05:48:46-47 | firewall-drop `delete`; alert 652 Host Unblocked (600 s) | W4_17, W4_18, W4_19 |

Configuration: `<active-response>` block appended to `/var/ossec/etc/ossec.conf` on wazuh-server (W4_13); backup `ossec.conf.bak-week4`.

## Limitations
- The block is local to the attacked host: the same source can still reach ubuntu-victim2.
- 192.168.56.1 (admin workstation) is not in `<white_list>`; six mistyped passwords would lock the admin out of that host for 10 minutes. Recommended: add it to the white list.
- Only rule 100010 is automated. One test run; block latency measured once.
- A 10-minute block does not stop a patient attacker; step 4 exists for that.
