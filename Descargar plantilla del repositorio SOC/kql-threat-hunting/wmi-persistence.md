# WMI Persistence Detection

## Objective

Detect suspicious WMI event subscriptions that could be used by attackers to establish persistence on a Windows endpoint.

## MITRE ATT&CK

- T1546.003 - Event Triggered Execution: WMI Event Subscription

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

## Data Source

- Microsoft Defender for Endpoint
- DeviceEvents

## Threat Scenario

An attacker creates a WMI Event Filter and Consumer to execute malicious code automatically when a specific system event occurs. This allows persistence without relying on traditional startup locations.

## Analyst Investigation Steps

1. Review WMI-related events.
2. Identify newly created WMI subscriptions.
3. Verify whether the activity is legitimate.
4. Analyze associated processes and scripts.
5. Investigate endpoint activity preceding the event.
6. Search for similar persistence mechanisms on other devices.

## Expected Findings

- WMI event subscriptions
- Persistence mechanisms
- Malware execution
- Unauthorized administrative activity

## Severity

High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Persistence | T1546.003 |
| Execution | T1546.003 |

## Remediation

- Remove unauthorized WMI subscriptions.
- Investigate the source of the activity.
- Isolate compromised endpoints if necessary.
- Reset affected credentials.
- Monitor for recurring WMI persistence activity.
```
