# Suspicious Rundll32 Execution Detection

## Objective

Detect potentially malicious usage of Rundll32.exe, a legitimate Windows utility often abused by attackers to execute malicious DLLs and evade security controls.

## MITRE ATT&CK

- T1218.011 - Rundll32

## KQL Query

```kusto
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine !has "shell32.dll"
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

An attacker abuses Rundll32.exe to execute malicious code through DLL files while appearing as a legitimate Windows process. This technique is frequently used for defense evasion and malware execution.

## Analyst Investigation Steps

1. Review the command line parameters.
2. Identify the DLL being loaded.
3. Verify whether the DLL is trusted.
4. Review the parent process.
5. Investigate related endpoint activity.
6. Determine whether persistence mechanisms exist.

## Expected Findings

- Malicious DLL execution
- Living-off-the-land activity
- Malware execution
- Defense evasion attempts

## Severity

Medium-High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Defense Evasion | T1218.011 |
| Execution | T1218.011 |

## Remediation

- Investigate affected endpoints.
- Isolate compromised devices.
- Remove malicious DLLs.
- Block associated indicators.
- Review endpoint security controls.
```
