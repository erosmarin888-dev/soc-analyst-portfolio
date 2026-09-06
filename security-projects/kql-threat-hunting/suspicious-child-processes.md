# Suspicious Child Process Detection

## Objective

Detect suspicious child processes spawned by Microsoft Office applications, which may indicate phishing, malware execution, or macro-based attacks.

## MITRE ATT&CK

- T1204.002 - User Execution: Malicious File
- T1059 - Command and Scripting Interpreter

## KQL Query

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE",
    "EXCEL.EXE",
    "POWERPNT.EXE",
    "OUTLOOK.EXE"
)
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe"
)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine
| order by TimeGenerated desc
```

## Data Source

- Microsoft Defender for Endpoint
- DeviceProcessEvents

## Threat Scenario

An attacker delivers a malicious Office document containing macros or embedded content. When the document is opened, it launches a child process such as PowerShell or CMD to execute malicious code.

## Analyst Investigation Steps

1. Identify the parent Office application.
2. Review the command line arguments.
3. Determine whether the document originated externally.
4. Analyze related email activity.
5. Review additional process execution on the endpoint.
6. 
