# Password Spray Analytics Rule

## Overview

This project demonstrates the creation of a Microsoft Sentinel Analytics Rule designed to detect password spray attacks against Microsoft Entra ID accounts.

## Objective

Identify multiple failed authentication attempts from a single IP address targeting multiple user accounts within a short timeframe.

## MITRE ATT&CK

- T1110.003 - Password Spraying

## Data Sources

- Microsoft Entra ID
- SigninLogs
- Microsoft Sentinel

## Detection Logic

The analytic rule identifies IP addresses generating repeated failed sign-in attempts against multiple accounts, which may indicate a password spray attack.

## KQL Query

```kusto
SigninLogs
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedUsers = dcount(UserPrincipalName)
by IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 20
| where TargetedUsers >= 5
| project
    TimeGenerated,
    IPAddress,
    FailedAttempts,
    TargetedUsers
| order by FailedAttempts desc
```

## Analytics Rule Configuration

### Rule Name

```text
Password Spray Detection
```

### Severity

```text
High
```

### Tactics

```text
Credential Access
```

### Techniques

```text
T1110.003 - Password Spraying
```

### Query Schedule

```text
Run query every: 5 minutes
```

### Lookup Data

```text
Last 15 minutes
```

### Trigger Threshold

```text
Greater than 0 results
```

## Investigation Workflow

1. Identify the source IP address.
2. Determine how many accounts were targeted.
3. Review authentication locations.
4. Check if successful authentications occurred after failures.
5. Review MFA events.
6. Investigate related incidents.

## Expected Findings

- Password spray attacks
- Credential stuffing attempts
- Unauthorized access attempts
- Reconnaissance activity

## False Positives

- Authentication testing
- Identity synchronization issues
- Misconfigured applications

## Response Actions

1. Block malicious IP addresses.
2. Force password reset for affected accounts.
3. Review Conditional Access policies.
4. Enable MFA if not already configured.
5. Monitor affected users for further activity.

## Lessons Learned

Password spraying remains one of the most common identity-based attacks. Monitoring authentication failures across multiple accounts provides early visibility into credential access attempts and helps prevent account compromise.

## Technologies Used

- Microsoft Sentinel
- Microsoft Entra ID
- Kusto Query Language (KQL)
- Microsoft Security Operations

## References

- Microsoft Sentinel Analytics Rules
- MITRE ATT&CK T1110.003 - Password Spraying
```
