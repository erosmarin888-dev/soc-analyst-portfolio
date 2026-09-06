# Dormant Account Logon Detection

## Objective

Identify successful sign-ins from accounts that have not been used for an extended period of time. Dormant accounts are attractive targets for attackers because their activity may go unnoticed.

## MITRE ATT&CK

- T1078 - Valid Accounts

## KQL Query

```kusto
let DormantThreshold = 30d;

let RecentLogons =
SigninLogs
| where ResultType == 0
| summarize LastSeen = max(TimeGenerated) by UserPrincipalName;

RecentLogons
| where LastSeen < ago(DormantThreshold)
| project
    UserPrincipalName,
    LastSeen
| order by LastSeen asc
```

## Data Source

- Microsoft Entra ID
- SigninLogs

## Threat Scenario

An attacker gains access to an inactive account and uses it to establish persistence, evade detection, or move laterally within the environment.

## Analyst Investigation Steps

1. Identify the account owner.
2. Determine why the account was inactive.
3. Review recent authentication activity.
4. Check source IP addresses.
5. Investigate privilege assignments.
6. Disable the account if unauthorized activity is confirmed.

## Expected Findings

- Compromised dormant accounts
- Unauthorized account usage
- Persistence attempts
- Insider threat activity

## Severity

Medium

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Persistence | T1078 |
| Defense Evasion | T1078 |
| Initial Access | T1078 |

## Remediation

- Disable unused accounts.
- Review account lifecycle processes.
- Reset credentials if compromise is suspected.
- Enforce MFA.
- Periodically audit inactive accounts.
```
