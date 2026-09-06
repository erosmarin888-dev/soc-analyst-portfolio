# Ransomware Investigation Case Study

> **Portfolio Disclaimer:** This is a simulated SOC investigation created for educational and portfolio purposes. All users, devices, domains, IP addresses, file hashes, alerts, and findings are fictional. No confidential or production information is included.

## Executive Summary

Microsoft Defender XDR generated a high-severity alert after detecting suspicious file encryption activity on a Windows endpoint.

The affected device showed rapid file modifications, unusual file extensions, execution of an untrusted binary, attempted deletion of recovery information, and network connections to an unknown external destination.

The investigation was initiated to:

- Validate whether ransomware execution occurred.
- Identify the initial access and execution path.
- Determine the affected user and endpoint.
- Evaluate potential lateral movement.
- Identify impacted files and systems.
- Contain the affected endpoint.
- Preserve evidence for escalation.
- Recommend eradication and recovery actions.

## Alert Information

| Field | Value |
|---|---|
| Alert Name | Suspected Ransomware Activity |
| Severity | Critical |
| Status | Investigated |
| Classification | Simulated True Positive |
| Detection Source | Microsoft Defender for Endpoint |
| Investigation Platform | Microsoft Defender XDR |
| SIEM Platform | Microsoft Sentinel |
| Primary MITRE ATT&CK Technique | T1486 - Data Encrypted for Impact |
| Environment | Simulated Lab |

## Incident Description

A Windows endpoint generated alerts after an executable launched from the user's Downloads directory and began modifying multiple files.

Several files received an unfamiliar extension, and a text file resembling a ransom note appeared shortly afterward.

### Simulated suspicious executable

```text
C:\Users\lab-user\Downloads\invoice_viewer.exe
```

### Simulated encrypted file extension

```text
.locked
```

### Simulated ransom note

```text
RECOVER_FILES.txt
```

> These values are fictional examples created for the lab scenario.

## Investigation Objectives

The objectives were to:

1. Confirm whether encryption activity occurred.
2. Identify the initiating process and process tree.
3. Determine how the suspicious file entered the endpoint.
4. Identify persistence or defense-evasion behavior.
5. Review network connections associated with the process.
6. Search for similar activity across other endpoints.
7. Determine whether lateral movement was attempted.
8. Assess the potential business impact.
9. Recommend immediate containment and recovery actions.
10. Document the investigation for escalation.

## Initial Evidence

The simulated alert contained the following indicators:

- Execution of an unsigned binary from the Downloads directory.
- Rapid modification of files in user-accessible directories.
- Creation of files using an unfamiliar extension.
- Creation of a ransom-note-style text file.
- Execution of commands associated with recovery inhibition.
- Connections to an unknown external destination.
- Multiple suspicious child processes.

## Incident Timeline

| Time | Simulated Event |
|---|---|
| 09:02 | User downloads `invoice_viewer.exe` |
| 09:04 | Suspicious executable is launched |
| 09:05 | PowerShell is started as a child process |
| 09:06 | Recovery-related commands are executed |
| 09:07 | Numerous files are modified |
| 09:08 | Files begin receiving the `.locked` extension |
| 09:09 | `RECOVER_FILES.txt` is created |
| 09:10 | Defender XDR generates a ransomware alert |
| 09:12 | SOC investigation begins |
| 09:15 | Simulated endpoint containment is recommended |

## Investigation Process

### Step 1: Validate the Alert

The alert was reviewed to confirm:

- Device name.
- User account.
- Alert severity.
- Detection timestamp.
- Process command line.
- File location.
- File hash.
- Process ancestry.
- Related alerts.
- Defender XDR automated investigation results.

The behavior involved several ransomware-related indicators and required immediate investigation.

### Step 2: Review the Process Tree

The process tree was examined to determine:

- Which process launched the suspicious executable.
- Whether the user initiated the execution.
- Which child processes were created.
- Whether PowerShell or the command prompt was involved.
- Whether system utilities were abused.
- Whether the activity originated from an email attachment or browser download.

### Process investigation query

```kql
let SuspiciousFile = "invoice_viewer.exe";
DeviceProcessEvents
| where FileName =~ SuspiciousFile
    or InitiatingProcessFileName =~ SuspiciousFile
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256,
    ReportId
| order by Timestamp asc
```

### Step 3: Review File Activity

File events were analyzed to identify:

- The number of files modified.
- Newly created extensions.
- Directories affected.
- Ransom note creation.
- Encryption patterns.
- Related file hashes.

### File modification query

```kql
let SuspiciousDevice = "LAB-WIN11-01";
DeviceFileEvents
| where DeviceName =~ SuspiciousDevice
| where ActionType in (
    "FileCreated",
    "FileModified",
    "FileRenamed"
)
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    PreviousFileName,
    PreviousFolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp asc
```

### Search for the simulated encrypted extension

```kql
DeviceFileEvents
| where FileName endswith ".locked"
| summarize
    AffectedFiles = count(),
    FirstObserved = min(Timestamp),
    LastObserved = max(Timestamp)
    by DeviceName, InitiatingProcessFileName
| order by AffectedFiles desc
```

### Search for ransom-note-style files

```kql
DeviceFileEvents
| where FileName in~ (
    "RECOVER_FILES.txt",
    "README_RESTORE.txt",
    "HOW_TO_DECRYPT.txt"
)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

> File names in this query are simulated examples. They are not intended to represent a complete list of ransomware indicators.

### Step 4: Review Recovery Inhibition Activity

The investigation reviewed whether the suspicious process attempted to interfere with recovery mechanisms.

### Recovery inhibition hunting query

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "wbadmin delete catalog",
    "bcdedit /set",
    "reagentc /disable"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### Step 5: Review Network Activity

Network telemetry associated with the suspicious process was reviewed for:

- Unknown external IP addresses.
- Newly observed domains.
- Command-and-control activity.
- Payload downloads.
- Possible data exfiltration.
- Connections from related processes.

### Network investigation query

```kql
let SuspiciousFile = "invoice_viewer.exe";
DeviceNetworkEvents
| where InitiatingProcessFileName =~ SuspiciousFile
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256
| order by Timestamp asc
```

### Step 6: Determine the Initial Access Vector

The investigation considered several possible entry points:

- Malicious email attachment.
- Phishing link.
- Browser download.
- Exploitation of a vulnerable service.
- Unauthorized remote access.
- Compromised credentials.
- Removable media.

For this simulated scenario, browser download activity immediately preceded execution of the suspicious binary.

### Browser download correlation query

```kql
let SuspiciousDevice = "LAB-WIN11-01";
DeviceFileEvents
| where DeviceName =~ SuspiciousDevice
| where FolderPath contains "\\Downloads\\"
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    FileOriginUrl,
    FileOriginReferrerUrl,
    InitiatingProcessFileName,
    SHA256
| order by Timestamp asc
```

### Step 7: Search for Lateral Movement

The scope review searched for:

- Remote service creation.
- SMB activity.
- RDP connections.
- Remote PowerShell.
- Use of administrative shares.
- Authentication from the affected device.
- Execution of the same file on other endpoints.

### Search for the same file hash across endpoints

```kql
let SuspiciousHash = "REPLACE_WITH_SIMULATED_SHA256";
DeviceProcessEvents
| where SHA256 == SuspiciousHash
| summarize
    FirstObserved = min(Timestamp),
    LastObserved = max(Timestamp),
    ExecutionCount = count()
    by DeviceName, AccountName, FileName, FolderPath
| order by ExecutionCount desc
```

### Search for suspicious remote activity

```kql
DeviceLogonEvents
| where LogonType in ("Remote interactive", "Network")
| project
    Timestamp,
    DeviceName,
    AccountName,
    RemoteIP,
    LogonType,
    ActionType,
    InitiatingProcessFileName
| order by Timestamp desc
```

> Replace placeholders only with fictional lab information or sanitized data that you are authorized to publish.

### Step 8: Determine the Scope

The analyst should identify:

- Number of affected devices.
- Number of impacted users.
- Number and type of modified files.
- Whether shared drives were accessed.
- Whether privileged accounts were involved.
- Whether the malware executed elsewhere.
- Whether backups or recovery mechanisms were affected.
- Whether sensitive data may have been accessed or exfiltrated.

## Findings

The simulated investigation identified:

- Execution of an untrusted binary from the user’s Downloads directory.
- Rapid file modification originating from the suspicious process.
- Creation of files using the simulated `.locked` extension.
- Creation of a simulated ransom note.
- PowerShell and command-line activity associated with the execution chain.
- Attempted interference with recovery mechanisms.
- Network communication from the suspicious process.
- No confirmed execution of the same file on additional endpoints in the simulated dataset.

The combined indicators were consistent with ransomware behavior.

## Root Cause Analysis

The simulated root cause was:

**Execution of an untrusted file downloaded from a malicious website and launched by the user without validation of its source or reputation.**

The executable initiated file modification activity and attempted to interfere with endpoint recovery capabilities.

The attack was enabled by the following simulated conditions:

- The downloaded executable was allowed to launch.
- The file originated from an untrusted external source.
- The user believed the file was a legitimate invoice viewer.
- Endpoint controls detected the activity after execution began.
- The process obtained sufficient access to modify files in the user context.

### Root cause chain

```text
Malicious website
        ↓
User downloads untrusted executable
        ↓
User launches executable
        ↓
Suspicious child processes execute
        ↓
Recovery inhibition attempted
        ↓
Files modified and renamed
        ↓
Ransom note created
        ↓
Defender XDR alert generated
```

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Relevance |
|---|---|---|---|
| Execution | User Execution: Malicious File | T1204.002 | User launches the downloaded executable |
| Execution | PowerShell | T1059.001 | PowerShell is used in the process chain |
| Defense Evasion | Impair Defenses | T1562.001 | Security or recovery controls may be targeted |
| Impact | Inhibit System Recovery | T1490 | Recovery mechanisms are targeted |
| Impact | Data Encrypted for Impact | T1486 | Files are encrypted or made inaccessible |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | Relevant when investigating network propagation |

> The mapping reflects the simulated behaviors described in this case. A real investigation should only map techniques supported by collected evidence.

## Potential Business Impact

If successful, this activity could result in:

- Loss of access to business files.
- Endpoint or service downtime.
- Operational disruption.
- Financial loss.
- Data recovery expenses.
- Potential exposure of sensitive information.
- Compromise of additional systems.
- Loss of customer or stakeholder trust.
- Regulatory or contractual reporting requirements.

## Potential False Positives

Potential benign explanations should be evaluated before final classification:

- Approved encryption software.
- Backup or file synchronization tools.
- Bulk file-renaming utilities.
- Authorized administrative scripts.
- Software deployment or migration activity.
- Security testing performed with prior approval.

In this simulated scenario, the ransom note, recovery-inhibition commands, suspicious executable, and rapid file changes reduced the likelihood of a benign explanation.

## Severity and Prioritization

**Severity:** Critical

### Prioritization factors

- Active file modification.
- Potential destruction of availability.
- Possible propagation to other endpoints.
- Possible interference with recovery.
- Potential impact to shared data.
- Need for immediate 
