# Source-IP and context enrichment

| IP | Type | Context | Intel result |
|---|---|---|---|
| 192.168.56.103 | RFC1918 private (host-only network) | Internal asset inventory: Kali attacker VM | Public reputation sources do not apply to private addresses; attribution done through the internal inventory. Source of all 13 network-based alerts. |
| 192.168.56.1 | RFC1918 private | Admin workstation, origin of authorized sudo/FIM tests | Known/trusted internal host |
| 192.168.56.111 / .113 | RFC1918 private | Victim servers | Internal assets |

## Reasoning
- No public IP appears in any incident, so external threat-intel lookups (VirusTotal, AbuseIPDB) were not applicable in Week 3. External IOC enrichment is planned for Week 4.
- Enrichment value in Week 3 comes from **asset context**: who owns the source, what the target does, how critical it is, and whether the activity matches an approved change.
- In a real SOC, an alert from an unknown internal IP with no inventory match would be escalated one severity level.
