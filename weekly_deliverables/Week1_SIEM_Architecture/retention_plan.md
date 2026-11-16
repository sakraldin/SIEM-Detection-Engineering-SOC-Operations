# Log Retention Plan

**Scope:** medium-size organization (about 300 endpoints) + the lab implementation on Wazuh 4.14.10
**Principle:** keep recent data fast and searchable, keep older data cheap and compressed, delete only after the legal/compliance period.

---

## 1. Retention tiers (target design for the organization)

| Tier | Age | Storage | Purpose | Searchable in Dashboard |
|---|---|---|---|---|
| Hot | 0–30 days | Indexer on fast disk (SSD) | Daily triage, active investigations, correlation rules | ✅ Immediately |
| Warm | 31–90 days | Indexer, lower-cost disk | Incident look-back, threat hunting | ✅ Yes |
| Cold / Archive | 91 days – 12 months | Compressed files on cheap or offline storage | Compliance, forensics, late-discovered breaches | ⚠️ Restore first |
| Delete | After 12 months | n/a | Storage cost and privacy limits | ❌ |

Reference: PCI DSS requires keeping audit log history for at least 12 months, with at least the last 3 months immediately available for analysis. HIPAA and other regulations may require longer, so the final period must be confirmed with the organization's compliance team.

---

## 2. Retention by data source

| Source | Log type | Hot | Total retention | Reason |
|---|---|---|---|---|
| Endpoints (Linux/Windows) | Auth, sudo, process, FIM | 30 days | 12 months | Authentication and privilege events are core evidence |
| Domain Controller / Identity | Logon, account and group changes | 90 days | 12 months | Needed to trace lateral movement and persistence |
| Firewall / IDS | Allow/deny, alerts | 30 days | 12 months | Very high volume, so archive early |
| Cloud (AWS / Azure) | CloudTrail, Activity logs | 90 days | 12 months | Low volume, high investigative value |
| Application (Web / DB) | Access, error, queries | 30 days | 6 months | Medium value, high volume |
| Wazuh alerts (processed) | Rule matches | 90 days | 12 months | Small compared to raw logs, long value |
| Raw archives | Every event before filtering | 7 days | 3 months | Troubleshooting new decoders and rules |

---

## 3. Storage estimate (method)

```
Daily size = endpoints × average events per second × average event size × 86,400
```

Example with assumptions (to be adjusted with real measurements):

| Assumption | Value |
|---|---|
| Endpoints | 300 |
| Average events per endpoint | 0.5 per second |
| Average event size | 500 bytes |
| Daily volume | 300 × 0.5 × 500 × 86,400 ≈ **6.5 GB/day** |
| Hot (30 days) | ≈ 194 GB |
| Warm (60 days) | ≈ 389 GB |
| Archive (9 months, ~10:1 compression) | ≈ 160 GB |
| Safety margin | +30% |

The indexer also adds index overhead and replicas, so real disk need must be validated after a pilot period.

---

## 4. Lab implementation

| Item | Lab value |
|---|---|
| Wazuh VM disk | 50 GB |
| Data volume | Very low (one agent, 68 events in the first test) |
| Alerts retention (lab) | 30 days |
| Raw archive | Disabled (default), enabled only when debugging decoders |
| Disk check command | `df -h` on the Wazuh VM |
| Indexer size check | Dashboard → Indexer management → Index management → Indices |

Optional lab evidence (can be done later): create an Index State Management policy in the Dashboard that deletes `wazuh-alerts-4.x-*` indices after 30 days.

---

## 5. Controls around retention

1. **Integrity:** archived logs stored read-only, with checksums, to keep their value as evidence.
2. **Access:** only the SOC team can read logs, and only admins can delete or change retention.
3. **Time sync:** all sources use NTP and UTC, otherwise old and new events cannot be correlated.
4. **Legal hold:** logs related to an open incident are excluded from deletion until the case is closed.
5. **Monitoring:** alert when the Wazuh disk usage exceeds 80%, and when an agent stops sending logs.
6. **Review:** retention periods are reviewed once a year or when regulations change.
