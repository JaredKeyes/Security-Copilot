# Suspicious Security Group Change Runbook

## Overview

This runbook describes how to investigate suspicious AWS security group ingress changes, especially changes that expose systems to the internet.

## Common Indicators

- AuthorizeSecurityGroupIngress from an unusual principal
- Ingress rule allowing 0.0.0.0/0
- Security group change followed by RunInstances
- Changes from suspicious or unfamiliar IP addresses
- Security group modification by a service account outside deployment windows

## Investigation Steps

1. Identify the security group that was modified.
2. Review who made the change and from which IP address.
3. Determine whether the change opened access to sensitive ports.
4. Check whether the change was followed by new EC2 instance creation.
5. Compare the activity to expected deployment behavior.
6. Review whether the user or service account recently assumed a role.
7. Check for related GuardDuty findings.
8. Determine whether the change was approved.

## Containment Steps

- Revert unauthorized ingress rules.
- Restrict exposed ports.
- Isolate newly launched suspicious instances.
- Review service account permissions.
- Rotate credentials if account abuse is suspected.
- Preserve evidence before deleting resources.

## Evidence to Collect

- Security group modification event
- Source IP address
- User or role that made the change
- EC2 instance launch events
- Security group before and after state
- Deployment records
- GuardDuty findings

## Escalation Criteria

Escalate if the change exposed sensitive systems, came from a suspicious IP, involved privileged credentials, or was followed by suspicious compute activity.

## Related MITRE ATT&CK Techniques

- T1578 - Modify Cloud Compute Infrastructure
- T1078 - Valid Accounts