# T1546 - WMI Persistence Detection

## Description

Detect the creation or modification of WMI Event Subscriptions that may be used by attackers to maintain persistence and execute malicious code automatically when specific system events occur.

## MITRE ATT&CK

- T1546.003 - Event Triggered Execution: WMI Event Subscription

## Severity

High

## Data Source

- Microsoft Defender for Endpoint
- DeviceEvents

## Detection Logic

Identify WMI-related activity involving event filters, event consumers, and filter-to-consumer bindings commonly associated with persistence mechanisms.

## KQL Query

```kusto
DeviceEvents
| where ActionType contains "Wmi"
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated desc
```

## Investigation Steps

1. Review the WMI activity performed.
2. Identify newly created event filters or consumers.
3. Determine who initiated the action.
4. Review associated processes and scripts.
5. Investigate related endpoint activity.
6. Search for similar activity on other devices.

## Expected Findings

- WMI event subscriptions
- Persistence mechanisms
- Unauthorized administrative activity
- Malware execution
- Defense evasion attempts

## False Positives

- Legitimate administration tools
- Endpoint management solutions
- Approved automation scripts

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Persistence | T1546.003 |
| Execution | T1546.003 |

## Response Actions

- Remove unauthorized WMI subscriptions.
- Investigate affected endpoints.
- Review compromised accounts.
- Isolate suspicious devices if necessary.
- Monitor for recurring WMI activity.

## References

- MITRE ATT&CK T1546.003 - Event Triggered Execution: WMI Event Subscription
- Microsoft Defender for Endpoint
```
