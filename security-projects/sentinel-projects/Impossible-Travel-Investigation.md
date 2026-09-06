# Impossible Travel Investigation

## Overview

This project demonstrates the investigation of an Impossible Travel alert in Microsoft Sentinel. The objective is to determine whether the activity represents legitimate user behavior or a potential account compromise.

## Objective

Investigate successful authentications from geographically distant locations occurring within a timeframe that would be physically impossible for a user to travel between.

## MITRE ATT&CK

- T1078 - Valid Accounts

## Data Sources

- Microsoft Entra ID
- SigninLogs
- Microsoft Sentinel

## Detection Query

```kusto
let TimeWindow = 4h;

SigninLogs
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, Country
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | project TimeGenerated, UserPrincipalName, IPAddress, Country
) on UserPrincipalName
| where Country != Country1
| where TimeGenerated1 > TimeGenerated
| where TimeGenerated1 - TimeGenerated < TimeWindow
| project
    UserPrincipalName,
    FirstLoginTime = TimeGenerated,
    FirstCountry = Country,
    FirstIP = IPAddress,
    SecondLoginTime = TimeGenerated1,
    SecondCountry = Country1,
    SecondIP = IPAddress1,
    TimeDifference = TimeGenerated1 - TimeGenerated
```

## Alert Details

### Alert Name

```text
Impossible Travel Activity
```

### Severity

```text
Medium
```

### Tactics

```text
Initial Access
Persistence
Defense Evasion
```

### Technique

```text
T1078 - Valid Accounts
```

## Investigation Process

### Step 1 - Review User Activity

- Identify the user involved.
- Validate recent login history.
- Review successful and failed sign-in attempts.

### Step 2 - Analyze Source Locations

- Compare login locations.
- Determine travel feasibility.
- Investigate VPN usage.

### Step 3 - Review Authentication Factors

- Verify MFA activity.
- Review Conditional Access results.
- Check device compliance status.

### Step 4 - Investigate IP Addresses

- Review IP reputation.
- Identify hosting providers.
- Determine whether the IP is associated with VPN services.

### Step 5 - Assess Risk

Determine if the activity is:

- Legitimate travel
- Corporate VPN usage
- Suspicious authentication
- Confirmed account compromise

## Root Cause Analysis

Possible causes include:

- Stolen credentials
- Session hijacking
- VPN usage
- Legitimate user travel
- Shared credentials

## Response Actions

1. Validate activity with the user.
2. Revoke active sessions if necessary.
3. Force password reset.
4. Review MFA enrollment.
5. Investigate additional indicators of compromise.
6. Escalate confirmed compromises.

## Lessons Learned

Impossible travel detections are most effective when combined with MFA analysis, IP reputation checks, Conditional Access data, and user validation. Contextual investigation is required before classifying the activity as malicious.

## Technologies Used

- Microsoft Sentinel
- Microsoft Entra ID
- Kusto Query Language (KQL)
- Microsoft Security Operations
```
