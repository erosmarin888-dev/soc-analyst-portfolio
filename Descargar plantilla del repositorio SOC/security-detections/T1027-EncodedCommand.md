# T1027 - Encoded PowerShell Command Detection

## MITRE ATT&CK

| Technique | ID |
|------------|------------|
| Obfuscated Files or Information | T1027 |
| Encoded Commands | T1027.010 |

---

## Objective

Detect the use of encoded PowerShell commands that may be used to hide malicious activity from defenders and security tooling.

Threat actors frequently utilize Base64 encoded commands in PowerShell to evade detection and conceal the true purpose of their execution.

---

## Detection Logic

This detection identifies:

- Encoded PowerShell execution
- Base64 encoded command strings
- Obfuscated PowerShell activity
- Attempts to bypass security monitoring
- Suspicious command-line arguments

Common indicators include:

- -EncodedCommand
- -enc
- FromBase64String
- Invoke-Expression
- IEX
- Hidden PowerShell windows

---

## Microsoft Sentinel KQL Query

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand"
    or ProcessCommandLine contains "-enc"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Advanced Detection Query

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand"
    or ProcessCommandLine contains "-enc"
    or ProcessCommandLine contains "FromBase64String"
    or ProcessCommandLine contains "IEX"
| summarize Count=count()
by DeviceName,
   AccountName,
   ProcessCommandLine
| sort by Count desc
```

---

## Indicators of Compromise (IOC)

The following may indicate malicious activity:

- Base64 encoded command strings
- PowerShell launched from Office applications
- Encoded execution followed by network activity
- Script downloads from external sources
- Obfuscated command-line parameters
- PowerShell running as hidden processes

---

## Investigation Steps

1. Identify the affected device.
2. Review the initiating user account.
3. Decode the Base64 command if present.
4. Determine the parent process.
5. Review subsequent child processes.
6. Check Defender XDR alerts associated with the device.
7. Investigate outbound network connections.
8. Review persistence mechanisms created after execution.
9. Determine whether additional payloads were downloaded.
10. Assess whether credential access activity occurred.

---

## Threat Hunting Opportunities

Analysts should search for:

- Repeated encoded command executions
- Connections to suspicious domains
- Use of download cradles
- PowerShell activity outside business hours
- Execution originating from Office applications

Example hunt:

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-EncodedCommand"
| summarize Executions=count()
by DeviceName,
   AccountName
| sort by Executions desc
```

---

## Potential Impact

Successful execution may lead to:

- Malware installation
- Ransomware deployment
- Command and Control (C2)
- Credential theft
- Privilege escalation
- Lateral movement
- Data exfiltration

---

## False Positives

Legitimate sources may include:

- Administrative automation scripts
- Enterprise deployment tooling
- Endpoint management platforms
- Security team testing activities
- Internal automation runbooks

Validation of business context should always be performed before escalation.

---

## Response Actions

### Containment

- Isolate affected endpoint
- Block malicious processes
- Restrict outbound communications
- Disable compromised accounts if necessary

### Eradication

- Remove malicious scripts
- Delete unauthorized scheduled tasks
- Remove registry persistence entries
- Block identified Indicators of Compromise

### Recovery

- Restore affected systems
- Re-enable business services
- Monitor affected users and devices
- Verify environment integrity

---

## Detection Tuning Recommendations

Improve accuracy by:

- Excluding approved administration accounts
- Whitelisting authorized automation servers
- Baselining normal PowerShell usage
- Correlating with threat intelligence feeds
- Requiring additional suspicious indicators before alerting

---

## Related MITRE ATT&CK Techniques

| Technique | ID |
|-----------|-----------|
| PowerShell | T1059.001 |
| Obfuscated Files | T1027 |
| Valid Accounts | T1078 |
| Scheduled Tasks | T1053 |
| Command and Scripting Interpreter | T1059 |
| Account Manipulation | T1098 |

---

## SOC Analyst Notes

Encoded PowerShell commands are among the most common techniques observed during post-compromise activity.

The use of Base64 encoding alone is not always malicious. However, encoded commands combined with suspicious parent processes, network connections, or persistence activity significantly increase confidence that malicious behavior is occurring.

Correlation with Microsoft Defender XDR telemetry is strongly recommended.

---

## Detection Maturity

| Capability | Status |
|------------|---------|
| Encoded Command Detection | ✅ |
| Process Analysis | ✅ |
| Parent Process Correlation | ✅ |
| Threat Hunting Ready | ✅ |
| Defender XDR Compatible | ✅ |
| Microsoft Sentinel Compatible | ✅ |
| SOC Production Ready | ✅ |
