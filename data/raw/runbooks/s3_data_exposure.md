# S3 Data Exposure Runbook

## Overview

This runbook describes how to investigate possible unauthorized access to S3 buckets and objects.

## Common Indicators

- ListBuckets from an unusual IP address
- GetObject access to sensitive buckets
- Repeated AccessDenied errors during discovery
- Access from known malicious infrastructure
- S3 activity shortly after suspicious login or role assumption
- Access to customer, financial, backup, or production data buckets

## Investigation Steps

1. Identify the bucket and object accessed.
2. Review the principal that accessed the data.
3. Review CloudTrail events before and after the S3 access.
4. Check whether the source IP is known malicious or unusual.
5. Determine whether the access was expected for the user’s role.
6. Check for bulk access patterns or repeated object downloads.
7. Review whether new access keys were created before or after access.
8. Determine whether data exposure notification procedures are required.

## Containment Steps

- Restrict bucket access if unauthorized activity is confirmed.
- Rotate credentials for the affected principal.
- Review bucket policies and IAM permissions.
- Enable or verify S3 data event logging.
- Preserve access logs and CloudTrail evidence.
- Notify legal, privacy, or compliance teams if sensitive data was exposed.

## Evidence to Collect

- S3 ListBuckets and GetObject events
- Bucket and object names
- User or role identity
- Source IP address
- IAM permissions
- Access key metadata
- Related GuardDuty findings

## Escalation Criteria

Escalate if sensitive data was accessed, downloaded, exposed publicly, or accessed by a compromised user.

## Related MITRE ATT&CK Techniques

- T1530 - Data from Cloud Storage
- T1619 - Cloud Storage Object Discovery