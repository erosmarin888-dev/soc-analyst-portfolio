# T1218 - LOLBins Abuse Detection

## Description

Detect the abuse of Living Off the Land Binaries (LOLBins), legitimate Windows binaries commonly leveraged by attackers to execute malicious code, download payloads, establish persistence, or evade security controls.

## MITRE ATT&CK

- T1218 - System Binary Proxy Execution

## Severity

Medium-High

## Data Source

- Microsoft Defender for Endpoint
- DeviceProcessEvents

## Detection Logic

Identify execution of commonly abused Windows binaries frequently observed in adversary operations.

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

## Investigation Steps

1. Identify the executed LOLBin.
2. Review command-line arguments.
3. Determine whether the activity was authorized.
4. Examine the parent process.
5. Check for downloaded files or network 
