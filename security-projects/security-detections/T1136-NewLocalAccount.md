# T1136 - New Local Account Creation Detection

## Overview

This detection identifies the creation of new user accounts on Windows endpoints.

Attackers commonly create local accounts to establish persistence, maintain access after remediation efforts, or facilitate privilege escalation.

Unauthorized account creation is a high-value security event that should be investigated immediately.

---

## MITRE ATT&CK Mapping

| Field | Value |
|--------|--------|
| Technique | Create Account |
| Technique ID | T1136 |
| Sub-Technique | Local Account |
| Sub-Technique ID | T1136.001 |
| Tactic | Persistence |
| Tactic | Privilege Escalation |
| Data Source | Microsoft Defender XDR |
| Detection Platform | Microsoft Sentinel |

---

## Objective

Detect newly created local accounts on Windows devices that may indicate:

- Persistence activity
- Unauthorized administrative access
- Post-compromise actions
- Insider misuse
- Privilege escalation attempts

---

## Threat Description

Threat actors frequently create local accounts after gaining access to an endpoint.

These accounts may be:

- Hidden from users
- Added to local administrators
- Used for Remote Desktop access
- Used to maintain persistence

The newly created account often survives password resets performed on compromised domain accounts.

---

## Data Requirements

Required telemetry:

- DeviceEvents
- DeviceProcessEvents
- Identity information
- Microsoft Defender for Endpoint

Optional telemetry:

- Windows Security Event Logs
- Defender XDR incidents
- Microsoft Entra ID sign-in activity

---

## Detection Logic

Monitor for:

- User account creation events
- New local administrator accounts
- Execution of account creation commands
- Account creation followed by privilege assignment

Common commands include:

```cmd
net user support_admin Password123! /add
```

```cmd
net localgroup administrators support_admin /add
```

```powershell
New-LocalUser
```

```powershell
Add-LocalGroupMember
```

---

## Microsoft Sentinel KQL Query

```kql
DeviceEvents
| where ActionType == "UserAccountCreated"
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    ActionType
| sort by Timestamp desc
```

---

## Advanced Detection Query

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "net user"
    or ProcessCommandLine contains "New-LocalUser"
    or ProcessCommandLine contains "Add-LocalGroupMember"
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

---

## High-Risk Account Creation Detection

Identify accounts immediately added to privileged groups.

```kql
DeviceEvents
| where ActionType in (
    "UserAccountCreated",
    "UserAccountAddedToLocalGroup"
)
| summarize
    Actions=count()
by DeviceName,
   AccountName
| where Actions > 1
```

---

## Investigation Steps

### Step 1

Identify:

- Newly created account
- Device involved
- Time of creation

### Step 2

Determine:

- Who created the account
- Which process was responsible

### Step 3

Review:

- Related account modifications
- Local group membership additions
- Administrator group assignments

### Step 4

Investigate:

- Defender incidents
- Malware alerts
- PowerShell activity
- Command execution history

### Step 5

Determine:

- Legitimate administrative change
- Unauthorized persistence activity

---

## Indicators of Suspicious Activity

Prioritize investigation when:

- Account name resembles a service account
- Account created outside business hours
- Account immediately added to Administrators
- Creation initiated by PowerShell
- Creation initiated by cmd.exe
- System recently compromised
- Defender alerts already exist

Examples:

- helpdesk_backup
- supportsvc
- updater_admin
- system_support

---

## Potential Impact

Successful abuse may result in:

- Persistence
- Privilege Escalation
- Remote Access
- Lateral Movement
- Defense Evasion
- Compromised Administrator Access

---

## False Positives

Legitimate causes include:

- IT administration
- New workstation setup
- Application installation
- Security testing
- Imaging processes
- Authorized support activities

Analysts should verify change records before escalation.

---

## Response Actions

### Containment

- Disable suspicious account
- Remove account from administrator groups
- Restrict remote access
- Isolate affected device

### Eradication

- Delete unauthorized accounts
- Remove backdoor access
- Remove unauthorized group memberships
- Review all related account activity

### Recovery

- Validate local accounts
- Confirm privileged memberships
- Re-enable authorized access
- Continue monitoring

---

## Detection Tuning Recommendations

Improve detection quality by:

- Baseline expected local account creation
- Maintain approved account lists
- Alert when administrators are added
- Correlate with Defender incidents
- Correlate with PowerShell activity
- Correlate with risky sign-ins

Avoid excluding administrator activity entirely because compromised administrators can perform identical actions.

---

## Severity Guidance

| Severity | Condition |
|------------|------------|
| Low | Authorized account creation |
| Medium | Unusual account creation |
| High | Account added to Administrators |
| Critical | Account creation associated with confirmed compromise |

---

## Related MITRE ATT&CK Techniques

| Technique | ID |
|------------|------------|
| Create Account | T1136 |
| Local Account | T1136.001 |
| Valid Accounts | T1078 |
| Account Manipulation | T1098 |
| PowerShell | T1059.001 |
| Command and Scripting Interpreter | T1059 |

---

## Detection Validation

Perform the following test:

1. Create a local test account.

```cmd
net user LabUser Password123! /add
```

2. Add the account to Administrators.

```cmd
net localgroup administrators LabUser /add
```

3. Verify events appear in Defender XDR.

4. Confirm query returns expected telemetry.

5. Validate alert logic.

---

## SOC Analyst Notes

Creation of unauthorized local accounts is one of the most common persistence mechanisms observed during post-compromise investigations.

Analysts should treat administrator account creation with elevated priority, especially when combined with PowerShell activity, malware alerts, suspicious authentication patterns, or other persistence techniques.

---

## Detection Maturity

| Capability | Status |
|------------|---------|
| MITRE Mapped | ✅ |
| Defender XDR Compatible | ✅ |
| Sentinel Compatible | ✅ |
| Threat Hunting Ready | ✅ |
| Investigation Workflow Included | ✅ |
| Response Playbook Included | ✅ |
| Portfolio Ready | ✅ |
