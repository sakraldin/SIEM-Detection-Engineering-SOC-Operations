# Scripted fields (index pattern: soc-triage, language: Painless, type: number)

## mttd_seconds
```painless
if (doc['attack_started'].size() == 0 || doc['detected_at'].size() == 0) { return null; }
return (doc['detected_at'].value.toInstant().toEpochMilli() - doc['attack_started'].value.toInstant().toEpochMilli()) / 1000.0;
```

## mttr_minutes
```painless
if (doc['closed_at'].size() == 0 || doc['detected_at'].size() == 0) { return null; }
return (doc['closed_at'].value.toInstant().toEpochMilli() - doc['detected_at'].value.toInstant().toEpochMilli()) / 60000.0;
```
