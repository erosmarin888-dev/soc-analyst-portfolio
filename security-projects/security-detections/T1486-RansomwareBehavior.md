# T1486 - Data Encrypted for Impact (Ransomware Behavior Detection)

## Overview

This detection identifies ransomware-like behavior on Windows endpoints.

Ransomware commonly performs large-scale file encryption, deletes backups, disables recovery mechanisms, and modifies large numbers of files in a short period.

Detecting these behaviors early can significantly reduce business impact and improve response effectiveness.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique | Data Encrypted for Impact |
| Technique ID | T1486 |
| Tactic | Impact |
| Data Source | Microsoft Defender XDR |
| Detection Platform | Microsoft Sentinel |
| Primary Tables | DeviceFileEvents, DeviceProcessEvents |

---

## Objective

Identify devices exhibiting behaviors commonly associated with ransomware attacks.

Detect:

- Mass file modifications
- Mass file renames
- File encryption activity
- Backup deletion attempts
- Recovery inhibition
- Suspicious encryption processes

---

## Threat Description

Ransomware operators aim to deny access to files by encrypting them.

Common ransomware behavior includes:

- Rapid modification of files
- Creation of encrypted file extensions
- Deletion of shadow copies
- Backup destruction
- Service termination
- System recovery manipulation

Attackers often perform these actions shortly before displaying a ransom note.

---

## Data Requirements

Required:

- Microsoft Defender for Endpoint
- DeviceFileEvents
- DeviceProcessEvents
- Microsoft Sentinel

Recommended:

- Defender XDR incidents
- Threat Intelligence
- Windows Security Logs

---

## Detection Logic

Monitor for:

- High-volume file operations
- One process modifying hundreds of files
- Shadow copy deletion
- Backup removal
- Unusual file extensions
- Encryption-related command execution

Indicators become more suspicious when multiple behaviors occur together.

---

## Microsoft Sentinel KQL Query

### Mass File Modification Detection

```kql
DeviceFileEvents
| summarize ModifiedFiles=count()
    by DeviceName,
       InitiatingProcessFileName,
       bin(Timestamp, 5m)
| where ModifiedFiles > 100
| order by ModifiedFiles desc
```

---

## Shadow Copy Deletion Detection

```kql
DeviceProcessEvents
| where ProcessCommandLine has "vssadmin"
| where ProcessCommandLine has "delete"
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine
```

---

## Backup Deletion Detection

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "wbadmin",
    "bcdedit",
    "vssadmin"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine
```

---

## Advanced Behavioral Detection

```kql
DeviceFileEvents
| summarize
    FileOperations=count()
by DeviceName,
   InitiatingProcessFileName,
   bin(Timestamp, 10m)
| where FileOperations > 250
| order by FileOperations desc
```

---

## Common Ransomware Commands

Examples frequently associated with ransomware activity:

```cmd
vssadmin delete shadows /all /quiet
```

```cmd
wbadmin delete catalog
```

```cmd
bcdedit /set recoveryenabled no
```

```cmd
bcdedit /set bootstatuspolicy ignoreallfailures
```

Detection of these commands does not confirm ransomware but should trigger investigation.

---

## Investigation Steps

### Step 1

Identify:

- Affected device
- Suspicious process
- User context

### Step 2

Determine:

- Number of modified files
- Impacted directories
- Encryption indicators

### Step 3

Review:

- Defender incidents
- Antivirus detections
- File activity timeline

### Step 4

Investigate:

- Initial infection vector
- PowerShell activity
- Email attachments
- Downloads
- Lateral movement activity

### Step 5

Determine:

- Scope of compromise
- Impacted systems
- Potential spread

---

## Indicators of Suspicious Activity

Elevate severity when:

- Hundreds of files are modified
- File extensions change rapidly
- Shadow copies are deleted
- Recovery settings are modified
- Security tools are disabled
- Defender alerts are present
- Unknown executables perform modifications

---

## Potential Impact

Successful ransomware execution may result in:

- File encryption
- Business interruption
- Data loss
- Recovery delays
- Financial loss
- Data exfiltration
- Regulatory impact

---

## False Positives

Potential legitimate causes:

- Large software installations
- Backup software
- Data migration projects
- File synchronization tools
- System upgrades

Analysts should verify the initiating process and business context.

---

## Response Actions

### Containment

- Isolate affected devices immediately
- Block malicious hashes
- Disable malicious accounts
- Restrict network communications

### Eradication

- Remove malware
- Remove persistence mechanisms
- Block known indicators
- Investigate lateral movement

### Recovery

- Restore from backups
- Validate system integrity
- Re-enable business services
- Continue monitoring

---

## Detection Tuning Recommendations

Improve accuracy by:

- Baselining file activity
- Monitoring trusted applications separately
- Excluding approved backup software
- Correlating process and file telemetry
- Combining behavioral detections

Avoid relying on file-count thresholds alone.

---

## Threat Hunting Opportunities

Hunt for:

- Devices modifying large numbers of files
- Shadow copy deletion attempts
- Recovery disabling commands
- Rare file extensions
- Unusual file write patterns
- Unknown executables modifying data

---

## Severity Guidance

| Severity | Condition |
|---|---|
| Medium | Unusual file activity |
| High | Mass modification activity |
| Critical | Encryption activity with recovery deletion |

---

## Related MITRE ATT&CK Techniques

| Technique | ID |
|---|---|
| Data Encrypted for Impact | T1486 |
| Inhibit System Recovery | T1490 |
| PowerShell | T1059.001 |
| Command and Scripting Interpreter | T1059 |
| Obfuscated Files | T1027 |
| Account Manipulation | T1098 |

---

## Detection Validation

Validation steps:

1. Generate controlled file activity in a test environment.
2. Confirm file events appear in Defender telemetry.
3. Run detection queries.
4. Validate alert thresholds.
5. Review generated results.
6. Tune based on observed activity.

---

## SOC Analyst Notes

Ransomware detection should never rely on a single indicator.

The highest-confidence detections correlate:

- File modifications
- Process behavior
- Recovery deletion
- Defender alerts
- Threat intelligence

Behavioral correlation significantly improves detection quality and reduces false positives.

---

## Detection Maturity

| Capability | Status |
|---|---|
| MITRE ATT&CK Mapped | ✅ |
| Defender XDR Compatible | ✅ |
| Sentinel Compatible | ✅ |
| Threat Hunting Ready | ✅ |
| Investigation Workflow Included | ✅ |
| Response Guidance Included | ✅ |
| Portfolio Ready | ✅ |
