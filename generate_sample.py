"""
Generate realistic AWS CloudTrail-style log files (JSON).
This script produces a CloudTrail-like JSON object with a top-level "Records" array.
It uses only Python stdlib so you can run it without extra packages.

Notes:
- Structure and field names follow AWS CloudTrail examples:
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html

Usage:
    python gen_cloudtrail.py --count 10 --out cloudtrail_sample.json --gzip False

(You asked not to run it here — save this file and run locally.)

"""

import json
import random
import uuid
import argparse
import gzip
from datetime import datetime, timedelta, timezone

# ---- Configurable pools to make generated logs look varied ----
AWS_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1",
    "eu-north-1", "ap-northeast-1"
]

EVENT_SOURCES = {
    "ec2.amazonaws.com": ["RunInstances", "TerminateInstances", "DescribeInstances"],
    "s3.amazonaws.com": ["GetObject", "PutObject", "DeleteObject", "CreateBucket"],
    "iam.amazonaws.com": ["CreateUser", "DeleteUser", "AttachUserPolicy", "CreateAccessKey"],
    "sts.amazonaws.com": ["AssumeRole", "GetCallerIdentity"],
    "lambda.amazonaws.com": ["CreateFunction20150421", "Invoke", "UpdateFunctionConfiguration"],
    "rds.amazonaws.com": ["CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance"],
    "cloudtrail.amazonaws.com": ["StartLogging", "StopLogging"],
    "kms.amazonaws.com": ["Decrypt", "Encrypt", "GenerateDataKey"],
}

USER_TYPES = ["IAMUser", "AssumedRole", "Root", "AWSService", "FederatedUser"]

USER_AGENTS = [
    "aws-cli/2.2.0 Python/3.8.8 Linux/4.14.232-176.381.amzn2.x86_64",
    "console.amazonaws.com",
    "Boto3/1.17.27 Python/3.8.10",
    "signin.amazonaws.com",
    "aws-sdk-java/2.16.12 linux-x86_64"
]

IP_PREFIXES = ["3.5.140.", "34.201.12.", "52.95.110.", "18.196.30.", "44.240.12."]

# Random vendor/account-like IDs to vary account IDs and ARNs
SAMPLE_ACCOUNT_IDS = ["012345678901", "111122223333", "210987654321", "555566667777"]
SAMPLE_PRINCIPAL_IDS = ["AIDAEXAMPLEID1", "AROAEXAMPLEID2", "ANONEXAMPLEID3"]
SAMPLE_ACCESS_KEYS = ["AKIAEXAMPLE1", "ASIAEXAMPLE2", "AKIAEXAMPLE3"]

# ---- Helper functions ----
def rand_iso8601(start_days_ago=7, end_days_ago=0):
    """Return an ISO8601 UTC timestamp between now - start_days_ago and now - end_days_ago."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=start_days_ago)
    end = now - timedelta(days=end_days_ago)
    rand_time = start + (end - start) * random.random()
    return rand_time.isoformat(timespec="seconds").replace("+00:00", "Z")

def rand_ip():
    prefix = random.choice(IP_PREFIXES)
    last = random.randint(1, 254)
    return f"{prefix}{last}"

def make_user_identity():
    utype = random.choice(USER_TYPES)
    account = random.choice(SAMPLE_ACCOUNT_IDS)
    principal = random.choice(SAMPLE_PRINCIPAL_IDS)
    access_key = random.choice(SAMPLE_ACCESS_KEYS)
    # Build several userIdentity shapes depending on type
    if utype == "IAMUser":
        return {
            "type": "IAMUser",
            "principalId": principal,
            "arn": f"arn:aws:iam::{account}:user/{random.choice(['alice','bob','charlie','david'])}",
            "accountId": account,
            "accessKeyId": access_key,
            "userName": random.choice(["alice","bob","charlie","david"]),
        }
    elif utype == "AssumedRole":
        return {
            "type": "AssumedRole",
            "principalId": principal + ":" + str(uuid.uuid4())[:8],
            "arn": f"arn:aws:sts::{account}:assumed-role/{random.choice(['Admin','Developer'])}/{random.choice(['alice','bob'])}",
            "accountId": account,
            "sessionContext": {
                "attributes": {
                    "creationDate": rand_iso8601(30, 0),
                    "mfaAuthenticated": random.choice(["true","false"])
                }
            },
        }
    elif utype == "Root":
        return {
            "type": "Root",
            "principalId": account,
            "arn": f"arn:aws:iam::{account}:root",
            "accountId": account,
            "accessKeyId": access_key
        }
    elif utype == "AWSService":
        svc = random.choice(["cloudtrail.amazonaws.com","config.amazonaws.com","guardduty.amazonaws.com"])
        return {
            "type": "AWSService",
            "principalId": svc,
            "arn": f"arn:aws:iam::{account}:role/service-role/{svc.split('.')[0]}",
            "accountId": account,
        }
    else:  # FederatedUser or fallback
        return {
            "type": "FederatedUser",
            "principalId": principal,
            "arn": f"arn:aws:sts::{account}:federated-user/{random.choice(['userX','userY'])}",
            "accountId": account,
            "userName": random.choice(["federatedUser1","federatedUser2"])
        }

def make_request_response_for(event_source, event_name):
    """
    Create small requestParameters and responseElements examples that match the service & action.
    Keep them compact but realistic.
    """
    if "s3" in event_source:
        key = f"test-file-{random.randint(1,9999)}.txt"
        return {
            "requestParameters": {"bucketName": f"example-bucket-{random.randint(1,50)}", "key": key},
            "responseElements": {"x-amz-request-id": str(uuid.uuid4())}
        }
    if "ec2" in event_source:
        return {
            "requestParameters": {"instancesSet": {"items": [{"instanceType": random.choice(["t3.medium","t3.small"])}]}},
            "responseElements": {"instancesSet": {"items": [{"instanceId": f"i-{uuid.uuid4().hex[:8]}"}]}}
        }
    if "iam" in event_source:
        return {
            "requestParameters": {"userName": random.choice(["new-user", "service-account"])},
            "responseElements": {"user": {"userName": random.choice(["new-user","service-account"]), "arn": f"arn:aws:iam::{random.choice(SAMPLE_ACCOUNT_IDS)}:user/new-user"}}
        }
    if "lambda" in event_source:
        return {
            "requestParameters": {"functionName": f"fn_{random.randint(1,100)}"},
            "responseElements": {"functionArn": f"arn:aws:lambda:{random.choice(AWS_REGIONS)}:{random.choice(SAMPLE_ACCOUNT_IDS)}:function:fn_{random.randint(1,100)}"}
        }
    if "kms" in event_source:
        return {
            "requestParameters": {"encryptionContext": {"purpose": "demo"}},
            "responseElements": {"keyId": f"arn:aws:kms:{random.choice(AWS_REGIONS)}:{random.choice(SAMPLE_ACCOUNT_IDS)}:key/{uuid.uuid4()}"}
        }
    # default fallback
    return {
        "requestParameters": {"param": "value"},
        "responseElements": {"status": "success"}
    }

def make_resource_list(event_source, event_name):
    # Some events include a "resources" array with ARN and type
    if "s3" in event_source:
        return [{"ARN": f"arn:aws:s3:::{random.choice(['example-bucket-1','example-bucket-2'])}", "accountId": random.choice(SAMPLE_ACCOUNT_IDS)}]
    if "ec2" in event_source:
        return [{"ARN": f"arn:aws:ec2:{random.choice(AWS_REGIONS)}:{random.choice(SAMPLE_ACCOUNT_IDS)}:instance/{uuid.uuid4().hex[:8]}", "accountId": random.choice(SAMPLE_ACCOUNT_IDS)}]
    return []

# ---- Main generator ----
def generate_cloudtrail_record():
    event_source = random.choice(list(EVENT_SOURCES.keys()))
    event_name = random.choice(EVENT_SOURCES[event_source])
    region = random.choice(AWS_REGIONS)
    user_identity = make_user_identity()
    event_time = rand_iso8601(14, 0)
    record = {
        "eventVersion": random.choice(["1.08", "1.11", "1.05"]),
        "userIdentity": user_identity,
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": rand_ip(),
        "userAgent": random.choice(USER_AGENTS),
        "requestParameters": {},
        "responseElements": {},
        "eventID": str(uuid.uuid4()),
        "readOnly": random.choice(["true","false"]),
        "resources": make_resource_list(event_source, event_name),
        # Optionally include other fields CloudTrail commonly has:
        "eventType": random.choice(["AwsApiCall", "AwsServiceEvent"]),
        "recipientAccountId": random.choice(SAMPLE_ACCOUNT_IDS)
    }

    rr = make_request_response_for(event_source, event_name)
    record["requestParameters"] = rr.get("requestParameters", {})
    record["responseElements"] = rr.get("responseElements", {})
    # Occasionally add error info
    if random.random() < 0.08:
        record["errorCode"] = random.choice(["AccessDenied", "ThrottlingException", "InvalidParameter"])
        record["errorMessage"] = "Simulated error for demo purposes"

    # Add session context sometimes
    if user_identity.get("type") == "AssumedRole" and "sessionContext" not in user_identity:
        record["sessionContext"] = {"sessionIssuer": {"type": "Role", "arn": user_identity.get("arn", "")}}

    return record

def generate_cloudtrail_log(num_records=5):
    # A realistic CloudTrail log file is a single JSON object with "Records": [ ... ]
    records = [generate_cloudtrail_record() for _ in range(num_records)]
    return {"Records": records}

# ---- CLI & file output ----
def main():
    parser = argparse.ArgumentParser(description="Generate CloudTrail-style JSON logs.")
    parser.add_argument("--count", type=int, default=10, help="Number of Records to generate")
    parser.add_argument("--out", default="cloudtrail_sample.json", help="Output filename (json or .json.gz)")
    parser.add_argument("--gzip", action="store_true", help="Compress output with gzip")
    args = parser.parse_args()

    payload = generate_cloudtrail_log(args.count)
    pretty = json.dumps(payload, indent=2, sort_keys=False)

    if args.gzip or args.out.endswith(".gz"):
        with gzip.open(args.out, "wt", compresslevel=6) as f:
            f.write(pretty)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(pretty)

    print(f"Wrote {args.count} Records to {args.out}")

if __name__ == "__main__":
    main()
