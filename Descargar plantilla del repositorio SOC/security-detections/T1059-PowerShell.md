# T1059 - PowerShell Execution Detection

## MITRE ATT&CK

| Technique | ID |
|------------|------------|
| Command and Scripting Interpreter: PowerShell | T1059.001 |

---

## Objective

Detect suspicious PowerShell activity that could indicate post-compromise actions, malicious scripting, credential theft, reconnaissance, persistence, or lateral movement.

PowerShell is commonly abused by attackers due to its native presence on Windows systems and its ability to execute code directly in memory.

---

## Detection Logic

This detection identifies:

- PowerShell process creation
- Encoded PowerShell commands
- Hidden PowerShell execution
- PowerShell launched by Office applications
- PowerShell spawned from unusual parent processes

Key indicators include:

- powershell.exe
- pwsh.exe
- -EncodedCommand
- -ExecutionPolicy Bypass
- -NoProfile
- -WindowStyle Hidden

---

## Microsoft Sentinel KQL Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName
| sort by Timestamp desc
```

```

---

## Advanced Detection Query

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand"
or ProcessCommandLine contains "-enc"
or ProcessCommandLine contains "-ExecutionPolicy Bypass"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName
```

---

## Investigation Steps

1. Identify the user who launched PowerShell.
2. Review the full command line.
3. Determine whether the command was encoded.
4. Identify the parent process.
5. Review Defender XDR alerts for the device.
6. Check for related persistence activity.
7. Investigate network connections created after execution.
8. Determine whether file downloads occurred.

---

## Suspicious Behaviors

The following activities may indicate malicious intent:

- Encoded PowerShell commands
- Download cradle activity
- Remote script execution
- Credential dumping attempts
- Registry modifications
- Scheduled task creation
- Privilege escalation actions

---

## Potential Impact

Successful exploitation may lead to:

- Remote Code Execution
- Credential Theft
- Malware Deployment
- Persistence
- Lateral Movement
- Data Exfiltration

---

## False Positives

Legitimate PowerShell usage may include:

- IT administrative scripts
- Patch management tools
- Configuration management
- Software deployment tools
- Internal automation tasks
- Security administration activities

---

## Response Actions

### Containment

- Isolate affected device
- Block malicious processes
- Disable compromised users if necessary

### Eradication

- Remove malicious scripts
- Remove persistence mechanisms
- Review scheduled tasks and registry changes

### Recovery

- Restore affected systems
- Re-enable services
- Monitor for recurring activity

---

## Detection Tuning Recommendations

To reduce noise:

- Exclude approved administrative accounts
- Exclude known automation servers
- Baseline normal PowerShell activity
- Alert only on encoded or hidden execution

---

## Related MITRE Techniques

| Technique | ID |
|------------|------------|
| PowerShell | T1059.001 |
| Encoded Commands | T1027 |
| Scheduled Tasks | T1053 |
| Valid Accounts | T1078 |
| Command Execution | T1059 |

---

## SOC Analyst Notes

PowerShell remains one of the most frequently abused tools in modern attacks. Monitoring encoded commands, hidden execution, and unusual parent-child process relationships significantly improves detection coverage.

This detection was designed for Microsoft Defender XDR and Microsoft Sentinel environments.

---

## Detection Maturity

| Level | Status |
|---------|----------|
| Basic Process Detection | ✅ |
| Encoded Command Detection | ✅ |
| Parent Process Analysis | ✅ |
| Threat Hunting Ready | ✅ |
| Production Ready | ✅ |
