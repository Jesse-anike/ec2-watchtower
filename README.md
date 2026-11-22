# EC2 WATCHTOWER — AWS EC2 Security Auditor

A read-only Python auditor for AWS CLI `describe-instances` JSON exports. It highlights EC2 instances with public IP addresses, IMDSv2 tokens not required, missing IAM instance profiles, and public DNS names on running instances.

## What it checks

- Public IPv4 address assigned to an instance.
- Instance Metadata Service v2 (IMDSv2) not enforced (`HttpTokens` is not `required`).
- Missing IAM instance profile.
- Public DNS name on a running instance.

## Requirements

- Python 3.10+
- Python standard library only
- No AWS credentials are required because the tool reads an exported JSON file.

## Export and run

Using AWS CLI with an identity authorized to describe EC2 instances:

```bash
aws ec2 describe-instances --output json > describe-instances.json
python main.py describe-instances.json
```

Read from standard input:

```bash
cat describe-instances.json | python main.py -
```

Save a report:

```bash
python main.py describe-instances.json --output ec2-security-report.json
```

## Test

```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Important interpretation notes

A public address or DNS name is not automatically a vulnerability; evaluate business need, security-group rules, subnet routes, network ACLs, workload design, and approved exposure. The tool does not call AWS APIs, modify resources, or remediate findings. It only reviews the supplied export.

## Safe use

Use AWS CLI only with an account and permissions you are authorized to use. Avoid committing real infrastructure exports because they may expose account, network, resource, or naming information. The included sample uses synthetic values.

## Portfolio context

Built for Anike-Moses Melie Jesse's defensive cybersecurity and cloud-security portfolio, demonstrating Python, AWS EC2 configuration review, IMDSv2 awareness, IAM visibility, JSON processing, and security-reporting fundamentals.
