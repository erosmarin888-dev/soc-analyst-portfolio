# T1003 - Credential Dumping Detection

## Description

Detect attempts to access or dump credentials from the Local Security Authority Subsystem Service (LSASS) memory. Attackers commonly use tools such as Mimikatz and ProcDump to harvest credentials for lateral movement and privilege escalation.

## MITRE ATT&CK

- T1003.001 - OS Credential Dumping: LSASS Memory

## Severity

High

## Data Source

- Microsoft Defender for Endpoint
- DeviceProcessEvents

## Detection Logic

Identify suspicious processes and command-line arguments commonly associated with credential dumping activity.

## KQL Query

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "mimikatz",
    "sekurlsa",
    "procdump",
    "lsass"
)
    or InitiatingProcessCommandLine has_any (
    "comsvcs.dll",
    "MiniDump"
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

## Investigation Steps

1. Identify the device involved.
2. Review the executed command line.
3. Determine whether LSASS access was legitimate.
4. Investigate the initiating process.
5. Review recent authentication activity.
6. Check for signs of lateral movement.

## Expected Findings

- Mimikatz execution
- ProcDump abuse
- Credential theft attempts
- LSASS memory access
- Privilege escalation activity

## False Positives

- Authorized forensic investigations
- Security tool testing
- Approved administrative activities

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Credential Access | T1003.001 |
| Privilege Escalation | T1003.001 |

## Response Actions

- Isolate affected endpoints.
- Reset compromised credentials.
- Review privileged account activity.
- Investigate lateral movement.
- Block malicious tools and indicators.

## References

- MITRE ATT&CK T1003.001 - OS Credential Dumping
- Microsoft Defender for Endpoint
```
