# AWS Credential Compromise Runbook

## Overview

This runbook describes how to investigate suspected AWS credential compromise involving IAM users, access keys, suspicious console logins, role assumptions, and unusual API activity.

## Common Indicators

- ConsoleLogin from an unfamiliar or known malicious IP address
- CreateAccessKey performed unexpectedly
- AssumeRole activity after suspicious login behavior
- S3 ListBuckets or GetObject activity from unusual locations
- AccessDenied errors during privilege discovery
- API calls from Tor exit nodes, botnets, scanners, or credential stuffing infrastructure

## Investigation Steps

1. Identify the principal involved in the alert.
2. Review CloudTrail events for the principal during the 24 hours before and after the alert.
3. Check whether the source IP address is known malicious or unusual for the user.
4. Look for access key creation, role assumption, S3 access, IAM changes, and attempts to disable logging.
5. Compare the activity to the user’s normal behavior.
6. Check whether MFA was enabled for the user.
7. Review whether the same IP address accessed other users, roles, or resources.
8. Determine whether sensitive data was accessed or exfiltrated.

## Containment Steps

- Disable or rotate suspicious access keys.
- Require password reset for the affected user.
- Revoke active sessions if supported.
- Temporarily restrict the user’s permissions.
- Block known malicious source IP addresses if appropriate.
- Preserve CloudTrail and GuardDuty evidence before making destructive changes.

## Evidence to Collect

- CloudTrail events for the user
- GuardDuty finding details
- IAM user metadata
- MFA status
- Access key creation time
- Source IP reputation
- S3 object access records
- Role assumption events

## Escalation Criteria

Escalate if the user accessed sensitive data, created new credentials, assumed privileged roles, disabled logging, or performed activity from known malicious infrastructure.

## Related MITRE ATT&CK Techniques

- T1078 - Valid Accounts
- T1098 - Account Manipulation
- T1530 - Data from Cloud Storage
- T1619 - Cloud Storage Object Discovery