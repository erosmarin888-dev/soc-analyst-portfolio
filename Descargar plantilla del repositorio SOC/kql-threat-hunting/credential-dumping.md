# Credential Dumping Detection

## Objective

Detect processes that attempt to access LSASS memory, which may indicate credential dumping activity commonly associated with tools such as Mimikatz.

## MITRE ATT&CK

- T1003.001 - OS Credential Dumping: LSASS Memory

## KQL Query

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "mimikatz")
    or InitiatingProcessCommandLine has_any ("procdump", "rundll32", "comsvcs.dll")
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated desc
```

## Data Source

- Microsoft Defender for Endpoint
- DeviceProcessEvents

## Threat Scenario

An attacker who has gained access to a system attempts to dump credentials from LSASS memory to obtain user passwords, NTLM hashes, or Kerberos tickets. These credentials can then be used for lateral movement and privilege escalation.

## Analyst Investigation Steps

1. Identify the device involved.
2. Review the process command line.
3. Determine whether the activity is legitimate.
4. Check for signs of lateral movement.
5. Investigate related account activity.
6. Isolate the affected endpoint if compromise is confirmed.

## Expected Findings

- Mimikatz execution
- Procdump abuse
- LSASS memory access
- Credential theft attempts
- Privilege escalation activity

## Severity

High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Credential Access | T1003.001 |
| Privilege Escalation | T1003.001 |

## Remediation

- Isolate affected devices.
- Reset compromised credentials.
- Investigate lateral movement activity.
- Review privileged account usage.
- Enable Microsoft Defender Attack Surface Reduction rules.
```
