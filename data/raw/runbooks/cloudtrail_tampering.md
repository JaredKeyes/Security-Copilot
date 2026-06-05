# CloudTrail Tampering Runbook

## Overview

This runbook describes how to investigate attempts to disable, modify, or delete AWS CloudTrail logging.

## Common Indicators

- StopLogging API call
- DeleteTrail API call
- UpdateTrail activity that weakens logging
- AssumeRole activity before logging changes
- CloudTrail changes from a suspicious IP address
- Logging changes performed by an unusual user or service account

## Investigation Steps

1. Identify the principal that performed the CloudTrail action.
2. Review events immediately before and after StopLogging or DeleteTrail.
3. Determine whether the user assumed a privileged role before modifying logging.
4. Check the source IP reputation and whether it is unusual for the user.
5. Review other actions by the same user and source IP address.
6. Confirm whether the CloudTrail change was approved.
7. Check whether GuardDuty, CloudWatch, or other monitoring tools also generated alerts.

## Containment Steps

- Re-enable CloudTrail logging immediately.
- Confirm logs are being delivered to the expected S3 bucket or log destination.
- Restrict the permissions of the principal that modified logging.
- Rotate credentials if compromise is suspected.
- Preserve available audit logs.
- Notify the incident response team.

## Evidence to Collect

- StopLogging and DeleteTrail events
- AssumeRole events before logging changes
- Source IP address and reputation
- User or role permissions
- CloudTrail configuration history
- Related GuardDuty findings

## Escalation Criteria

Escalate immediately if logging was disabled by an unauthorized user, from a suspicious IP address, after privilege escalation, or during other suspicious activity.

## Related MITRE ATT&CK Techniques

- T1562.008 - Disable Cloud Logs
- T1078 - Valid Accounts