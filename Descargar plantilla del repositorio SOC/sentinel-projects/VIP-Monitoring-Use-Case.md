# VIP User Monitoring Use Case

## Overview

This project demonstrates the design and implementation of a monitoring strategy for privileged and high-value accounts within Microsoft Sentinel.

## Objective

Provide enhanced monitoring and alerting for executive, administrative, and business-critical accounts that present a higher organizational risk if compromised.

## MITRE ATT&CK

- T1078 - Valid Accounts
- T1110 - Brute Force
- T1098 - Account Manipulation

## Data Sources

- Microsoft Entra ID
- SigninLogs
- AuditLogs
- Microsoft Sentinel

## Business Requirement

High-value accounts require additional monitoring due to their elevated privileges and access to sensitive business information.

Examples include:

- Global Administrators
- Security Administrators
- Executives
- Finance Personnel
- Human Resources Personnel

## Detection Query

```kusto
let VIPUsers = dynamic([
    "vip.user1@company.com",
    "vip.user2@company.com",
    "vip.user3@company.com"
]);

SigninLogs
| where UserPrincipalName in (VIPUsers)
| where ResultType != 0
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    ResultType
| order by TimeGenerated desc
```

## Monitoring Scenarios

### Authentication Monitoring

- Failed sign-ins
- Impossible travel activity
- MFA fatigue attempts
- Unusual locations

### Privilege Monitoring

- Role assignments
- Privileged role activation
- Permission changes

### Mailbox Monitoring

- Email forwarding rules
- Mailbox delegation
- Suspicious mailbox activity

## Analytics Rule Configuration

### Rule Name

```text
VIP User Activity Monitoring
```

### Severity

```text
High
```

### Query Schedule

```text
Every 5 minutes
```

### Trigger Threshold

```text
Any result generated
```

## Investigation Process

### Step 1

Identify the affected VIP account.

### Step 2

Review authentication activity.

### Step 3

Check MFA events.

### Step 4

Investigate source IP reputation.

### Step 5

Review privilege modifications.

### Step 6

Determine whether escalation is required.

## Expected Findings

- Unauthorized access attempts
- Account takeover activity
- Privilege escalation attempts
- Business Email Compromise
- Insider threat activity

## Response Actions

1. Contact the account owner.
2. Review authentication logs.
3. Reset credentials if required.
4. Revoke active sessions.
5. Escalate confirmed compromises.
6. Document findings within Sentinel.

## Lessons Learned

Monitoring high-value accounts provides early visibility into potentially severe security incidents and allows security teams to prioritize investigations based on business risk.

## Technologies Used

- Microsoft Sentinel
- Microsoft Entra ID
- Microsoft Defender XDR
- Kusto Query Language (KQL)

## References

- Microsoft Sentinel
- MITRE ATT&CK Framework
```
