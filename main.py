from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def analyze(text: str) -> dict:
    """Review an AWS CLI describe-instances JSON export without changing resources."""
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON: {exc}"}

    instances = []
    for reservation in data.get("Reservations", []):
        instances.extend(reservation.get("Instances", []))

    findings = []
    for instance in instances:
        instance_id = instance.get("InstanceId", "(unknown)")
        state = (instance.get("State") or {}).get("Name")

        public_ip = instance.get("PublicIpAddress")
        if public_ip:
            findings.append({
                "instance_id": instance_id,
                "severity": "review",
                "risk": "public_ipv4_assigned",
                "value": public_ip,
                "recommendation": "Confirm the public address is required and exposure is restricted by approved network controls.",
            })

        metadata = instance.get("MetadataOptions") or {}
        if metadata.get("HttpTokens") != "required":
            findings.append({
                "instance_id": instance_id,
                "severity": "high",
                "risk": "imds_v2_not_required",
                "value": metadata.get("HttpTokens"),
                "recommendation": "Review the instance configuration and require IMDSv2 where compatible.",
            })

        if not instance.get("IamInstanceProfile"):
            findings.append({
                "instance_id": instance_id,
                "severity": "review",
                "risk": "no_instance_profile",
                "value": None,
                "recommendation": "Confirm whether the workload needs an instance role; use least privilege when one is required.",
            })

        if state == "running" and instance.get("PublicDnsName"):
            findings.append({
                "instance_id": instance_id,
                "severity": "review",
                "risk": "running_instance_has_public_dns",
                "value": instance.get("PublicDnsName"),
                "recommendation": "Check intended internet exposure, security groups, subnet routes, and application controls.",
            })

    return {
        "instances_reviewed": len(instances),
        "findings": findings,
        "finding_count": len(findings),
        "note": "Review findings in context. This tool reads an AWS CLI JSON export and performs no AWS API calls or remediation.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Review AWS EC2 describe-instances JSON for common configuration risks."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="-",
        help="Path to an AWS CLI JSON export; use - or omit to read standard input.",
    )
    parser.add_argument("--output", help="Optional JSON report output path.")
    args = parser.parse_args()

    raw = (
        sys.stdin.read()
        if args.target == "-"
        else Path(args.target).read_text(encoding="utf-8", errors="replace")
    )
    report = analyze(raw)
    rendered = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")

    print(rendered)
    return 0 if "error" not in report else 2


if __name__ == "__main__":
    raise SystemExit(main())
