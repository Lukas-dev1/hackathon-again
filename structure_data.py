#!/usr/bin/env python3
"""
gdpr_report.py
--------------
Transform AWS CloudTrail-style logs into a compact GDPR compliance report
with a concise executive summary and vulnerability extraction.

Usage:
    python gdpr_report.py --in cloudtrail_sample.json --out gdpr_report.json
"""

import json, uuid, argparse, datetime as dt
from collections import Counter, defaultdict

WRITE_OPS = {
    "PutObject","DeleteObject","CreateBucket","RunInstances","TerminateInstances",
    "AttachUserPolicy","CreateUser","CreateAccessKey","UpdateFunctionConfiguration",
    "CreateFunction20150421","ModifyDBInstance","CreateDBInstance","DeleteDBInstance",
    "StartLogging","StopLogging","Encrypt","GenerateDataKey"
}

# ---- Helpers ----------------------------------------------------------------

def short_svc(event_source:str)->str:
    return event_source.split(".")[0] if event_source else "unknown"

def _to_bool(v):
    if isinstance(v, bool): return v
    if isinstance(v, str): return v.lower() == "true"
    return False

def to_compact(rec:dict)->dict:
    """Convert a CloudTrail record into a smaller, normalized dict and add light risk tags."""
    ui = rec.get("userIdentity", {}) or {}
    sess_attrs = (ui.get("sessionContext") or {}).get("attributes") or {}
    svc = short_svc(rec.get("eventSource",""))
    action = rec.get("eventName","")
    req = rec.get("requestParameters") or {}
    resp = rec.get("responseElements") or {}

    # minimal request/response whitelisting (keeps this compact)
    if svc=="s3":
        req = {"bucket": req.get("bucketName"), "key": req.get("key")}
        resp = {"req_id": resp.get("x-amz-request-id")}
    elif svc=="ec2":
        resp = {"instanceIds": [i.get("instanceId") for i in (resp.get("instancesSet") or {}).get("items",[])]}
    elif svc=="iam":
        req = {"userName": req.get("userName")}
    elif svc=="lambda":
        req = {"functionName": req.get("functionName")}
    elif svc=="kms":
        req = {"enc_ctx": (req.get("encryptionContext") or {}).get("purpose")}

    compact = {
        "t": rec.get("eventTime"),
        "svc": svc,
        "action": action,
        "actor": {
            "type": ui.get("type"),
            "arn": ui.get("arn"),
            "accountId": ui.get("accountId")
        },
        "acct": rec.get("recipientAccountId") or ui.get("accountId"),
        "region": rec.get("awsRegion"),
        "ip": rec.get("sourceIPAddress"),
        "ro": _to_bool(rec.get("readOnly")),
        "mfa": (sess_attrs.get("mfaAuthenticated") if isinstance(sess_attrs.get("mfaAuthenticated"), str)
                else ("true" if sess_attrs.get("mfaAuthenticated") else "false")) if sess_attrs else None,
        "req": {k:v for k,v in req.items() if v is not None},
        "resp": {k:v for k,v in resp.items() if v is not None},
        "err": {"code": rec.get("errorCode"), "msg": rec.get("errorMessage")} if rec.get("errorCode") else None,
        "id": rec.get("eventID")
    }

    # derive risk tags (fast heuristics, no external context required)
    risk_tags = []

    if compact["err"]:
        risk_tags.append("error_event")

    if svc == "cloudtrail" and action == "StopLogging":
        risk_tags.append("logging_disabled_attempt")

    if (svc == "iam" and action in {"AttachUserPolicy","CreateAccessKey","CreateUser","DeleteUser"}):
        risk_tags.append("privilege_change")

    if (compact["actor"]["type"] == "Root"):
        risk_tags.append("root_usage")

    if (compact["actor"]["type"] == "AssumedRole"):
        # treat missing or explicit "false" as not MFA (CloudTrail varies by source)
        if compact["mfa"] in (None, "false"):
            risk_tags.append("role_no_mfa")

    if svc == "s3" and action in {"PutObject","DeleteObject"}:
        risk_tags.append("s3_data_change")
    if svc == "s3" and action in {"GetObject"} and compact["ro"]:
        risk_tags.append("s3_data_access")

    if svc == "kms" and action in {"Decrypt"}:
        risk_tags.append("kms_decrypt_activity")

    compact["risk_tags"] = risk_tags
    return compact

def summarize(compact:list)->dict:
    """Build core statistics used by both report and short summary."""
    total = len(compact)
    svc_counts = Counter(c["svc"] for c in compact)
    regions = Counter(c["region"] for c in compact if c.get("region"))
    principals = Counter((c["actor"] or {}).get("arn") for c in compact if (c.get("actor") or {}).get("arn"))
    read = sum(1 for c in compact if c.get("ro"))
    write = sum(1 for c in compact if not c.get("ro") or c.get("action") in WRITE_OPS)
    errors = sum(1 for c in compact if c.get("err"))

    by_service = defaultdict(lambda: {"read":0,"write":0,"error":0})
    for c in compact:
        bucket = by_service[c["svc"]]
        if c.get("err"): bucket["error"] += 1
        if (not c.get("ro")) or (c.get("action") in WRITE_OPS): bucket["write"] += 1
        else: bucket["read"] += 1

    return {
        "highlights": {
            "total_events": total,
            "unique_principals": len(principals),
            "read_vs_write_ratio": {
                "read": round(read/total,2) if total else 0,
                "write": round(write/total,2) if total else 0
            },
            "error_rate": round(errors/total,3) if total else 0,
            "top_services": [{"service": s, "count": n} for s,n in svc_counts.most_common(5)]
        },
        "event_rollups": {
            "by_service": [{"service": s, "counts": c} for s,c in by_service.items()],
            "by_region": [{"region": r, "count": n} for r,n in regions.items()]
        },
        "actors": {
            "top_principals": [{"principal_arn": a, "events": n} for a,n in principals.most_common(10)]
        }
    }

# ---- Vulnerability extraction & executive summary ---------------------------

RISK_WEIGHTS = {
    "logging_disabled_attempt": 10,
    "root_usage": 8,
    "role_no_mfa": 7,
    "privilege_change": 6,
    "kms_decrypt_activity": 5,
    "s3_data_change": 5,
    "s3_data_access": 3,
    "error_event": 2
}

SEVERITY = {
    "logging_disabled_attempt": "critical",
    "root_usage": "high",
    "role_no_mfa": "high",
    "privilege_change": "high",
    "kms_decrypt_activity": "medium",
    "s3_data_change": "medium",
    "s3_data_access": "low",
    "error_event": "low"
}

OWNER_MAP = {
    # maps your Development Areas & Responsibilities
    "logging_disabled_attempt": "Security & Access Control",
    "root_usage": "Security & Access Control",
    "role_no_mfa": "Security & Access Control",
    "privilege_change": "Security & Access Control",
    "kms_decrypt_activity": "Security & Access Control",
    "s3_data_change": "AI / NLP Processing",   # e.g., add rules to flag sensitive buckets
    "s3_data_access": "AI / NLP Processing",
    "error_event": "Backend & Workflow Automation"
}

REMEDIATIONS = {
    "logging_disabled_attempt": "Block StopLogging with SCP; alert on attempts; verify CloudTrail is multi-region & immutable.",
    "root_usage": "Disable root API keys; enable root account MFA; create break-glass procedure only.",
    "role_no_mfa": "Require MFA for AssumeRole; enforce conditional IAM; add session policy checks.",
    "privilege_change": "Review Admin policy attachments; require approvals; monitor access key creations.",
    "kms_decrypt_activity": "Scope KMS key IAM; add CMK key policies; monitor decrypt rates & IP reputation.",
    "s3_data_change": "Enforce default encryption & bucket policies; require approvals for delete/write in sensitive buckets.",
    "s3_data_access": "Tag buckets with data classifications; add anomaly detection on GetObject spikes.",
    "error_event": "Alert on bursts; correlate with write ops; fix failing automation jobs."
}

def extract_vulnerabilities(compact:list)->dict:
    counts = Counter(t for c in compact for t in c.get("risk_tags", []))
    examples = defaultdict(list)
    for c in compact:
        for t in c.get("risk_tags", []):
            if len(examples[t]) < 3:  # cap per type
                examples[t].append({
                    "t": c["t"], "actor": (c.get("actor") or {}).get("arn"),
                    "svc": c["svc"], "action": c["action"], "region": c.get("region"),
                    "ip": c.get("ip"), "id": c.get("id")
                })

    findings = []
    for t, n in counts.most_common():
        findings.append({
            "type": t,
            "count": n,
            "severity": SEVERITY.get(t, "low"),
            "owner": OWNER_MAP.get(t, "Backend & Workflow Automation"),
            "recommendation": REMEDIATIONS.get(t, "Review and remediate."),
            "examples": examples[t]
        })

    # naive risk score: weighted events normalized to 0-100 (clip)
    weighted = sum(RISK_WEIGHTS.get(t,1) * n for t, n in counts.items())
    # normalize by log of event volume to avoid spiky scores on large datasets
    denom = max(1.0, 10.0 + (len(compact) ** 0.5))
    risk_score = int(min(100, round((weighted / denom) * 3)))  # tweak factor for readability

    # action plan grouped by owner
    actions_by_owner = defaultdict(list)
    for f in findings:
        actions_by_owner[f["owner"]].append({
            "issue": f["type"], "severity": f["severity"], "action": f["recommendation"]
        })

    return {
        "risk_score": risk_score,
        "findings": findings[:12],  # keep it short
        "actions_by_owner": actions_by_owner
    }

def make_short_summary(period_from, period_to, sums, vulns)->dict:
    hl = sums["highlights"]
    # pick top 3 risks for the executive line
    top3 = [
        {"type": f["type"], "count": f["count"], "severity": f["severity"]}
        for f in vulns["findings"][:3]
    ]
    return {
        "period": {"from": period_from, "to": period_to},
        "key_numbers": {
            "events": hl["total_events"],
            "unique_principals": hl["unique_principals"],
            "error_rate": hl["error_rate"],
            "top_services": hl["top_services"][:3]
        },
        "risk_score": vulns["risk_score"],
        "top_risks": top3,
        "owners": {owner: items for owner, items in vulns["actions_by_owner"].items()}
    }

# ---- Report builder ---------------------------------------------------------

def build_gdpr_report(records:dict, period_from:str, period_to:str)->dict:
    compact = [to_compact(r) for r in (records.get("Records") or [])]
    sums = summarize(compact)

    # GDPR-aligned evidence (kept terse)
    kms_events = [c for c in compact if c["svc"]=="kms"]
    iam_attach_admin = [c for c in compact if c["svc"]=="iam" and c["action"]=="AttachUserPolicy"]

    # Vulnerabilities + short executive summary
    vulns = extract_vulnerabilities(compact)
    short_summary = make_short_summary(period_from, period_to, sums, vulns)

    return {
        "report_meta": {
            "report_id": str(uuid.uuid4()),
            "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds")+"Z",
            "framework": "GDPR",
            "period": {"from": period_from, "to": period_to},
            "sources": [{"type":"cloudtrail","count": len(compact)}]
        },
        "short_summary": short_summary,            # ← concise, exec-ready
        "vulnerabilities": vulns,                  # ← deduped findings
        **sums,
        "gdpr_summary": {
            "article_5_2_accountability": {
                "status": "partially_met",
                "evidence": [{"type":"metric","name":"cloudtrail_coverage","note":"Events observed across services/regions"}]
            },
            "article_30_records_of_processing": {
                "status": "informational",
                "processing_observations": [
                    {"system": "Amazon S3", "purpose_inferred": "Storage/backup",
                     "evidence":[{"service":"s3","events": next((x['count'] for x in sums['highlights']['top_services'] if x['service']=='s3'),0)}]}
                ],
                "gaps": ["Need controller/DPO contacts, retention periods, recipients"]
            },
            "article_32_security": {
                "status": "partially_met",
                "findings": [
                    {"control":"KMS usage","observed": bool(kms_events),"events": len(kms_events)},
                    {"control":"Privileged policy attach","observed": bool(iam_attach_admin),"events": len(iam_attach_admin)}
                ]
            },
            "article_33_breach_notification": {
                "status": "no_incident_detected",
                "potential_incidents": [],
                "timer_rules": {"window_hours":72}
            }
        },
        "records_compact": compact[:200]  # keep JSON manageable
    }

# ---- CLI --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="infile", required=True, help="Input CloudTrail JSON file")
    parser.add_argument("--out", dest="outfile", required=True, help="Output GDPR report JSON file")
    parser.add_argument("--from", dest="period_from", default="2025-09-01T00:00:00Z")
    parser.add_argument("--to", dest="period_to", default="2025-09-30T23:59:59Z")
    args = parser.parse_args()

    with open(args.infile, "r", encoding="utf-8") as f:
        records = json.load(f)

    report = build_gdpr_report(records, args.period_from, args.period_to)

    with open(args.outfile, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"✅ Wrote GDPR report to {args.outfile}")

if __name__ == "__main__":
    main()
