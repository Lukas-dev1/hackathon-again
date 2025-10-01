# aggregator.py
import hashlib
from collections import defaultdict, Counter
from itertools import islice

def tpl_key(c):
    # build a compact key; customize fields as needed
    svc = c.get("svc") or "unknown"
    action = c.get("action") or "unknown"
    atype = (c.get("actor") or {}).get("type") or "unknown"
    bucket = (c.get("req") or {}).get("bucket") or "-"
    base = f"{svc}|{action}|{atype}|bucket={bucket}"
    # keep key readable; also return a stable hash if you prefer
    return base

def reservoir_add(resv, item, k=3):
    # simple reservoir: keep first k, stop at k (we only need a few examples)
    if len(resv) < k:
        resv.append(item)

def aggregate(compact_iter):
    templates = {}
    service_counts = Counter()
    region_counts = Counter()

    for c in compact_iter:
        service_counts[c.get("svc")] += 1
        if c.get("region"):
            region_counts[c["region"]] += 1

        key = tpl_key(c)
        t = templates.get(key)
        if not t:
            t = templates[key] = {
                "tpl_id": key,
                "svc": c.get("svc"), "action": c.get("action"),
                "actor_type": (c.get("actor") or {}).get("type"),
                "region_counts": Counter(),
                "actors_top": Counter(),
                "keys_top": Counter(),
                "errors": 0,
                "examples": [],
                "risk_tags": set()
            }

        if c.get("region"):
            t["region_counts"][c["region"]] += 1
        if (c.get("actor") or {}).get("arn"):
            t["actors_top"][(c["actor"]["arn"])] += 1
        if (c.get("req") or {}).get("bucket"):
            bp = (c["req"]["bucket"], (c["req"].get("key") or "")[:20])  # prefix-ish
            t["keys_top"][bp] += 1
        if c.get("err"):
            t["errors"] += 1

        for tag in (c.get("risk_tags") or []):
            t["risk_tags"].add(tag)

        reservoir_add(t["examples"], {
            "t": c.get("t"),
            "actor": (c.get("actor") or {}).get("arn"),
            "svc": c.get("svc"),
            "action": c.get("action"),
            "region": c.get("region"),
            "ip": c.get("ip"),
            "id": c.get("id")
        })

    # finalize shapes
    out_templates = []
    for t in templates.values():
        out_templates.append({
            **{k: t[k] for k in ("tpl_id","svc","action","actor_type","errors")},
            "region_counts": dict(t["region_counts"]),
            "actors_top": [{"arn": a, "count": n} for a,n in t["actors_top"].most_common(5)],
            "keys_top": [{"bucket": b, "prefix": p, "count": n} for (b,p),n in t["keys_top"].most_common(5)],
            "examples": t["examples"],
            "risk_tags": sorted(t["risk_tags"])
        })

    rollups = {
        "services_top": [{"service": s, "count": n} for s,n in service_counts.most_common(10)],
        "regions_top": [{"region": r, "count": n} for r,n in region_counts.most_common(10)]
    }
    return {"templates": out_templates, "rollups": rollups}
