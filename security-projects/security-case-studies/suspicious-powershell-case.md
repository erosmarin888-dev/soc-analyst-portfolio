# Suspicious PowerShell Activity Investigation Case Study

> Portfolio Disclaimer: This is a simulated SOC investigation created for educational and portfolio purposes.

## Executive Summary

Microsoft Defender for Endpoint generated an alert after detecting suspicious PowerShell execution on a workstation.

During the investigation, encoded PowerShell commands were observed attempting to download remote content and execute additional actions.

The activity was analyzed to determine whether it represented legitimate administration activity or malicious PowerShell abuse.

## Alert Information

| Field | Value |
|---------|---------|
| Alert Name | Suspicious PowerShell Execution |
| Severity | High |
| Status | Investigated |
| Platform | Microsoft Defender XDR |
| MITRE ATT&CK | T1059.001 |
| Environment | Simulated Lab |

---

## Incident Description

Microsoft Defender detected execution of PowerShell with suspicious command-line parameters.

Example:

```powershell
powershell.exe -EncodedCommand SQBFAFgA...
```

The activity triggered monitoring controls due to use of encoded commands.

---

## Objectives

- Review PowerShell execution.
- Decode suspicious commands.
- Review process lineage.
- Identify malicious behavior.
- Determine containment requirements.

---

## Investigation Process

### Step 1 - Review Alert

Validated:

- Device involved
- User account
- Process execution timeline
- Severity

### Step 2 - Review PowerShell Command

Reviewed:

- Command arguments
- Encoded content
- Network indicators
- Download behavior

### Step 3 - Review Parent Process

Investigated:

- Explorer.exe
- CMD.exe
- Office Applications
- Browser Activity

### Step 4 - Review Network Communication

Checked:

- DNS Requests
- External Connections
- Download Attempts
- IP Reputation

### Step 5 - Search For Persistence

Reviewed:

- Scheduled Tasks
- Services
- Registry Run Keys
- Startup Items

---

## Detection Logic

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-enc"
    or ProcessCommandLine contains "-EncodedCommand"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ProcessCommandLine
```

---

## Threat Hunting Activities

### Encoded Commands

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
```

### PowerShell Activity

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
```

### Network Connections

```kql
DeviceNetworkEvents
| order by Timestamp desc
```

---

## Findings

The investigation identified:

- Encoded PowerShell execution.
- Suspicious command-line arguments.
- Network communication attempts.
- Behavior commonly associated with malware delivery.

Further analysis indicated malicious intent.

---

## Root Cause Assessment

The activity was consistent with attacker use of PowerShell for post-exploitation actions.

Encoded commands were likely used to evade detection and conceal execution activity.

---

## MITRE ATT&CK Mapping

| Tactic | Technique
