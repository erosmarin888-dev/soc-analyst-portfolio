# T1071 - Command and Control (C2) Beaconing Detection

## Overview

This detection identifies devices that establish periodic outbound network communications that may indicate Command and Control (C2) beaconing activity.

Beaconing occurs when malware regularly "checks in" with an external server to receive commands, download payloads, or exfiltrate information.

Detection of beaconing behavior is a critical capability for Security Operations Centers and Threat Hunting teams.

---

## MITRE ATT&CK Mapping

| Field | Value |
|----------|----------|
| Technique | Application Layer Protocol |
| Technique ID | T1071 |
| Tactic | Command and Control |
| Data Source | Microsoft Defender XDR |
| Detection Platform | Microsoft Sentinel |
| Related Network Telemetry | DeviceNetworkEvents |

---

## Objective

Detect systems that exhibit communication patterns commonly associated with malware command and control infrastructure.

Identify:

- Repetitive outbound connections
- Suspicious external destinations
- Low-volume but regular communications
- Connections to newly observed domains
- Communications over HTTP, HTTPS, DNS, or WebSockets

---

## Threat Description

Modern malware rarely maintains constant communication with attackers.

Instead, malicious software commonly:

1. Connects to a remote host.
2. Waits a fixed interval.
3. Reconnects repeatedly.

This creates a predictable pattern known as beaconing.

Beaconing may support:

- Remote administration
- Malware updates
- Credential theft
- Data exfiltration
- Ransomware deployment
- Lateral movement coordination

---

## Data Requirements

Required telemetry:

- DeviceNetworkEvents
- Microsoft Defender for Endpoint
- Microsoft Sentinel

Recommended telemetry:

- Threat Intelligence Feeds
- Defender XDR Alerts
- DNS Logs
- Firewall Logs
- Proxy Logs

---

## Detection Logic

Look for:

- Recurring connections
- Same source device
- Same destination IP
- Same destination domain
- Similar intervals between connections
- Long duration persistence

Higher risk indicators:

- Rare domains
- Newly registered domains
- Known malicious infrastructure
- TOR exit nodes
- Foreign hosting providers

---

## Microsoft Sentinel KQL Query

```kql
DeviceNetworkEvents
| summarize ConnectionCount=count()
    by DeviceName,
       RemoteIP,
       RemoteUrl
| where ConnectionCount > 50
| sort by ConnectionCount desc
```

---

## Advanced Beaconing Query

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| summarize
    Connections=count(),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp)
    by DeviceName,
       RemoteIP,
       RemoteUrl
| where Connections > 20
| order by Connections desc
```

---

## Threat Hunting Query

Identify devices repeatedly contacting the same destination.

```kql
DeviceNetworkEvents
| summarize
    TotalConnections=count()
    by DeviceName,
       RemoteIP
| where TotalConnections > 100
| order by TotalConnections desc
```

---

## Investigation Steps

### Step 1

Identify:

- Host making the connection
- Destination IP
- Destination domain

### Step 2

Determine:

- Connection frequency
- Time interval consistency
- Connection duration

### Step 3

Review:

- Defender incidents
- AV alerts
- PowerShell execution
- Suspicious process activity

### Step 4

Identify:

- Process responsible for connection
- Parent process chain
- Executable path

### Step 5

Evaluate:

- Known business application
- Expected cloud service
- Potential malicious infrastructure

---

## Suspicious Indicators

Escalate priority if:

- Connections occur every few minutes
- Connections persist for days
- Domain not previously observed
- Process is PowerShell
- Process is command prompt
- Process originates from temp directory
- Defender generated malware alerts
- Device recently experienced suspicious authentication activity

---

## Common Malicious Parent Processes

Potentially suspicious:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
mshta.exe
rundll32.exe
regsvr32.exe
```

Additional scrutiny should be applied when these processes initiate the network traffic.

---

## Potential Impact

Beaconing may indicate:

- Active malware infection
- Remote attacker access
- Credential theft
- Data exfiltration
- Ransomware staging
- Lateral movement
- Persistent compromise

---

## False Positives

Legitimate causes include:

- Software updates
- Endpoint management tools
- Monitoring agents
- Backup software
- Cloud synchronization
- Security products
- VPN clients

Analysts should validate business justification before escalating.

---

## Response Actions

### Containment

- Isolate affected endpoint
- Block malicious domain
- Block malicious IP address
- Restrict outbound communications

### Eradication

- Remove malware
- Remove persistence mechanisms
- Investigate initial access vector
- Remove unauthorized tools

### Recovery

- Restore affected systems
- Validate network communications
- Monitor outbound traffic
- Reassess endpoint security posture

---

## Detection Tuning Recommendations

Improve detection by:

- Creating allowlists for known services
- Baselining normal outbound traffic
- Incorporating threat intelligence feeds
- Monitoring newly observed domains
- Tracking rare destination IPs
- Correlating with Defender incidents

Avoid excluding large categories of traffic without validation.

---

## Threat Hunting Opportunities

Hunt for:

- Rare domains
- Rare IP addresses
- Newly observed destinations
- Long-running outbound communications
- Systems exhibiting repetitive intervals
- Processes connecting to unknown infrastructure

---

## Severity Guidance

| Severity | Condition |
|------------|------------|
| Low | Known business communication |
| Medium | Unusual communication pattern |
| High | Persistent beaconing behavior |
| Critical | Beaconing associated with confirmed malware |

---

## Related MITRE ATT&CK Techniques

| Technique | ID |
|----------|----------|
| Application Layer Protocol | T1071 |
| PowerShell | T1059.001 |
| Obfuscated Files | T1027 |
| Valid Accounts | T1078 |
| Remote Services | T1021 |
| Data Exfiltration | T1041 |

---

## Detection Validation

Perform validation by:

1. Generating controlled outbound traffic.
2. Reviewing DeviceNetworkEvents telemetry.
3. Confirming connection frequency is logged.
4. Validating query results.
5. Testing alert thresholds.
6. Documenting baseline activity.

---

## SOC Analyst Notes

Beaconing is often one of the strongest indicators of an active compromise because the attacker usually requires ongoing communication with compromised systems.

Correlation with Defender XDR alerts, suspicious process execution, PowerShell activity, and identity-based detections dramatically increases confidence in a true positive finding.

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
