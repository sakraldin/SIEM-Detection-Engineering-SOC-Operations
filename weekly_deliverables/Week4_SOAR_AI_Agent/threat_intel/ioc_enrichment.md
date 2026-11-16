# Threat intelligence / IOC enrichment

## Scope
All lab addresses are private (192.168.56.0/24, RFC1918), so IP reputation services have nothing to say about them.
Enrichment was therefore demonstrated on a file indicator.

## Test: file hash IOC (EICAR standard anti-malware test file, harmless)
| Step | Result | Evidence |
|---|---|---|
| 1. Create `/etc/eicar_test.txt` (68 bytes) on ubuntu-victim | sha256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | W4_20 |
| 2. Wazuh FIM (realtime) raises rule 554 "File added to the system", level 5, 16 Nov 2026 05:56:11 UTC | Alert carries `syscheck.sha256_after` = same hash, md5 `44d88612fea8a8f36de82e1278abb02f` | W4_21 |
| 3. Analyst looks the hash up on VirusTotal | 65 of 67 engines flag it; label `virus.eicar/test` | W4_22 |
| 4. Verdict after enrichment | Known test file; in production this result would raise the case to high and trigger host triage | - |

## What the test shows
- Without enrichment the alert is level 5 ("file added") and looks routine. The hash lookup is what changes its priority.
- The lookup was manual (one analyst, one browser query).

## Not implemented
- Automatic lookup (Wazuh VirusTotal integration needs an API key and sends hashes to an external service).
- IP/domain reputation: not applicable to this lab's private addressing.
- No IOC list (CDB) rule was added, to avoid changing the tested rule chain late in the project.
