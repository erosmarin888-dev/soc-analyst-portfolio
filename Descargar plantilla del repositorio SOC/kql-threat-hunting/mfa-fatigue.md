# MFA Fatigue Detection

## Objective

Identify repeated MFA push notification requests that may indicate an MFA fatigue attack, where an attacker continuously sends authentication prompts hoping the user eventually approves one.

## MITRE ATT&CK

- T1621 - Multi-Factor Authentication Request Generation

## KQL Query

```kusto
SigninLogs
| where ResultType != 0
| where Status has_any ("MFA", "authentication")
| summarize MFARequests = count() by UserPrincipalName, bin(TimeGenerated, 15m)
| where MFARequests >= 5
| project
    TimeGenerated,
    UserPrincipalName,
    MFARequests
| order by MFARequests desc
```

## Data Source

- Microsoft Entra ID
- SigninLogs

## Threat Scenario

An attacker has valid credentials and repeatedly triggers MFA prompts for a target user. The attacker hopes the user becomes frustrated or confused and eventually approves the request, granting access.

## Analyst Investigation Steps

1. Contact the user.
2. Verify whether the MFA prompts were expected.
3. Review recent sign-in activity.
4. Check source IP addresses and locations.
5. Investigate additional signs of account compromise.
6. Force credential reset if necessary.

## Expected Findings

- MFA fatigue attacks
- Account takeover attempts
- Suspicious authentication activity
- Unauthorized sign-in attempts

## Severity

High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Credential Access | T1621 |
| Initial Access | T1621 |

## Remediation

- Reset affected credentials.
- Revoke active sessions.
- Enable number matching.
- Enable location-aware MFA policies.
- Review Conditional Access policies.
```
