# Service Account Abuse Runbook

## Overview

This runbook describes how to investigate suspicious activity involving service accounts, automation users, CI/CD identities, and deployment roles.

## Common Indicators

- Service account activity from an unfamiliar IP address
- AssumeRole activity outside normal deployment windows
- Security group changes by a CI/CD account
- EC2 instance launches after suspicious role assumption
- Access key creation for service accounts
- Activity from known malicious infrastructure

## Investigation Steps

1. Identify the service account or automation identity involved.
2. Review recent role assumptions.
3. Check whether the activity matches expected deployment behavior.
4. Review source IP address and location.
5. Check whether the service account modified infrastructure.
6. Look for security group changes, EC2 launches, IAM changes, or S3 access.
7. Review CI/CD logs if available.
8. Determine whether credentials may have been leaked.

## Containment Steps

- Disable or rotate service account credentials.
- Restrict service account permissions.
- Revert unauthorized infrastructure changes.
- Review CI/CD secrets and environment variables.
- Isolate suspicious compute resources.
- Preserve logs before making destructive changes.

## Evidence to Collect

- Service account CloudTrail events
- AssumeRole activity
- Source IP address
- CI/CD job logs
- Security group modifications
- EC2 launch events
- Access key metadata
- GuardDuty findings

## Escalation Criteria

Escalate if the service account performed privileged actions from a suspicious IP address, modified infrastructure unexpectedly, or accessed sensitive resources.

## Related MITRE ATT&CK Techniques

- T1078 - Valid Accounts
- T1578 - Modify Cloud Compute Infrastructure
- T1098 - Account Manipulation