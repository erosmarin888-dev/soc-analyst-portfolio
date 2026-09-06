# LOLBins Abuse Detection

## Objective

Detect the abuse of Living Off the Land Binaries (LOLBins), legitimate Windows binaries commonly leveraged by attackers to execute malicious commands, download payloads, or evade security controls.

## MITRE ATT&CK

- T1218 - System Binary Proxy Execution

## KQL Query

```kusto
DeviceProcessEvents
| where FileName in~ (
    "certutil.exe",
    "mshta.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wmic.exe"
)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by TimeGenerated desc
```

## Data Source

- Microsoft Defender for Endpoint
- DeviceProcessEvents

## Threat Scenario

Attackers leverage trusted Windows binaries to execute malicious content while blending in with normal operating system activity. This technique is frequently used to bypass application controls and avoid detection.

## Analyst Investigation Steps

1. Review the command line arguments.
2. Identify the parent process.
3. Determine whether the execution was authorized.
4. Investigate network connections associated with the process.
5. Check for payload downloads or script execution.
6. Correlate activity with other security alerts.

## Expected Findings

- Malicious file downloads
- Script execution
- Command and control activity
- Defense evasion attempts
- Malware execution

## Severity

Medium-High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Defense Evasion | T1218 |
| Execution | T1218 |

## Remediation

- Investigate affected devices.
- Block malicious indicators.
- Remove unauthorized payloads.
- Review endpoint security controls.
- Monitor recurring LOLBin activity.
```
