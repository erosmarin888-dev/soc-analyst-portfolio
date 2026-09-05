# New Local Administrator Detection

## Objective

Identify newly created local administrator accounts that could indicate persistence, privilege escalation, or unauthorized system access.

## MITRE ATT&CK

- T1136.001 - Create Account: Local Account

## KQL Query

```kusto
DeviceEvents
| where ActionType in ("UserAccountCreated", "LocalUserAccountCreated")
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    ActionType
| order by TimeGenerated desc
```

## Data Source

- Microsoft Defender for Endpoint
- DeviceEvents

## Threat Scenario

An attacker creates a local administrator account on a compromised endpoint to maintain persistence and retain access after initial compromise.

## Analyst Investigation Steps

1. Verify whether the account creation was authorized.
2. Identify who created the account.
3. Review recent endpoint activity.
4. Check for lateral movement attempts.
5. Determine whether administrative privileges were assigned.
6. Investigate related alerts and incidents.

## Expected Findings

- Unauthorized local account creation
- Persistence mechanisms
- Privilege escalation activity
- Insider threat actions

## Severity

High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Persistence | T1136.001 |
| Privilege Escalation | T1136.001 |

## Remediation

- Remove unauthorized accounts.
- Review administrative privileges.
- Reset affected credentials.
- Investigate associated activity.
- Monitor future account creation events.
```
