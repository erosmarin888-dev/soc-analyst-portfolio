# T1078 - Valid Accounts Detection

## Description

Detect suspicious authentication activity involving valid user accounts. Adversaries often use legitimate credentials obtained through phishing, password spraying, credential dumping, or account compromise to gain and maintain access.

## MITRE ATT&CK

- T1078 - Valid Accounts

## Severity

High

## Data Source

- Microsoft Entra ID
- SigninLogs

## Detection Logic

Identify successful sign-ins from unusual locations, devices, or IP addresses that may indicate unauthorized use of valid credentials.

## KQL Query

```kusto
SigninLogs
| where ResultType == 0
| summarize
    LoginCount = count(),
    DistinctCountries = dcount(Location)
by UserPrincipalName
| where DistinctCountries > 1
| project
    UserPrincipalName,
    LoginCount,
    DistinctCountries
| order by DistinctCountries desc
```

## Investigation Steps

1. Verify recent activity with the user.
2. Review source IP addresses.
3. Check geographic locations.
4. Investigate MFA activity.
5. Review privilege assignments.
6. Correlate with password spray or phishing alerts.

## Expected Findings

- Account compromise
- Stolen credentials
- Unauthorized account access
- VPN abuse
- Insider threat activity

## False Positives

- Business travel
- Corporate VPN usage
- Remote workforce activity

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Initial Access | T1078 |
| Persistence | T1078 |
| Defense Evasion | T1078 |
| Privilege Escalation | T1078 |

## Response Actions

- Reset affected credentials.
- Revoke active sessions.
- Review MFA enrollment.
- Investigate related alerts.
- Enable Conditional Access policies.

## References

- MITRE ATT&CK T1078 - Valid Accounts
- Microsoft Entra ID Sign-in Logs
```
