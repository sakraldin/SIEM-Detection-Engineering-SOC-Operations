#!/usr/bin/env python3
"""Compare agent runs against the Week 3 incident register. usage: compare.py label=file.json ..."""
import json, statistics, sys
TRUTH = {"CASE-001": ("true_positive", "high"), "CASE-002": ("true_positive", "medium"),
         "CASE-003": ("true_positive", "critical"), "CASE-004": ("true_positive", "high"),
         "CASE-005": ("true_positive", "high"), "CASE-006": ("true_positive", "high"),
         "CASE-007": ("true_positive", "critical"), "CASE-008": ("true_positive", None),
         "CASE-009": ("true_positive", "high"), "CASE-010": ("true_positive", "critical"),
         "CASE-011": ("false_positive", None)}
runs = {}
for arg in sys.argv[1:]:
    label, path = arg.split("=", 1)
    runs[label] = {r["case"]["case_id"]: r for r in json.load(open(path, encoding="utf-8"))}
def metrics(run, key):
    ok = danger = sev_ok = sev_n = flagged_danger = 0
    for cid, (tv, tsv) in TRUTH.items():
        s = run[cid]["suggestion"]; v = s.get(key, s["verdict"])
        ok += v == tv
        if tv == "true_positive" and v == "false_positive":
            danger += 1; flagged_danger += bool(s.get("checks"))
        if tsv:
            sev_n += 1; sev_ok += (s["severity"] == tsv)
    lat = [r["llm_seconds"] for r in run.values()]
    return ok, danger, flagged_danger, sev_ok, sev_n, statistics.mean(lat), sum(lat) / 60
print("| Case | Register | " + " | ".join(runs) + " |"); print("|---|---|" + "---|" * len(runs))
for cid, (tv, _) in TRUTH.items():
    cells = []
    for run in runs.values():
        s = run[cid]["suggestion"]; mv = s.get("model_verdict", s["verdict"])
        cells.append(s["verdict"] if mv == s["verdict"] else f"{mv} -> {s['verdict']}")
    print(f"| {cid} | {tv} | " + " | ".join(cells) + " |")
print()
for label, run in runs.items():
    for key in ("model_verdict", "verdict"):
        ok, d, fd, so, sn, m, tot = metrics(run, key)
        print(f"{label:6s} {key:13s}: agreement {ok}/11 ({100*ok/11:.1f}%), dangerous {d} (flagged by checks {fd}), severity exact {so}/{sn}, mean {m:.1f}s, total {tot:.1f} min")
