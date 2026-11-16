# INC-003 escalation — SBAR

**To:** SOC Lead / Incident Response
**From:** ammar (SOC analyst, L1)
**Priority:** Critical

**S — Situation**
Wazuh rule 100012 fired at 14:46:55 UTC: the same source IP (192.168.56.103) authenticated successfully to two servers, ubuntu-victim (.111) and ubuntu-victim2 (.113). This indicates possible lateral movement (T1021).

**B — Background**
The source first logged in at 14:41:54 UTC. Both targets are High-criticality Linux servers monitored by Wazuh agents 001 and 002. Earlier today the same source performed SSH brute force against ubuntu-victim (INC-001).

**A — Assessment**
True positive (simulated in the lab). Pattern: brute force → valid access → move to a second host. Severity Critical. Detection gap: pivots through an intermediate host are not correlated by the current rule.

**R — Recommendation**
1. Isolate both hosts from the network.
2. Reset credentials of the accounts used.
3. Review auth logs on both hosts and hunt for the same source IP elsewhere.
4. Approve a correlation rule for intermediate-host pivoting.
