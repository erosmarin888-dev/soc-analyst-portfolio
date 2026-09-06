# KQL Threat Hunting

This section of my SOC Analyst portfolio contains threat-hunting investigations developed using **Kusto Query Language (KQL)**.

The projects demonstrate how security telemetry can be analyzed to identify suspicious authentication activity, endpoint behavior, credential access attempts, command execution, and other indicators associated with common attack techniques.

The queries are designed around Microsoft security technologies such as:

- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- Microsoft Entra ID
- Azure Log Analytics

---

## Project Overview

Threat hunting is a proactive security process used to search for suspicious activity that may not have generated a traditional security alert.

Instead of waiting for a detection to trigger, a threat hunter develops a hypothesis, identifies the required telemetry, writes queries, analyzes the results, and determines whether the observed activity represents legitimate behavior or a potential security threat.

This collection demonstrates my ability to:

- Develop threat-hunting hypotheses
- Identify relevant security telemetry
- Write and explain KQL queries
- Analyze identity and endpoint activity
- Correlate events across multiple data sources
- Identify suspicious patterns and behaviors
- Map activity to MITRE ATT&CK
- Document investigation procedures
- Consider false positives
- Recommend containment and remediation actions

---

## Threat-Hunting Methodology

Each project follows a consistent investigation workflow.

### 1. Define the Hypothesis

The investigation begins with a security question or assumption.

Example:

> An attacker may be using encoded PowerShell commands to hide malicious activity on a compromised endpoint.

A clear hypothesis helps determine which data sources, fields, and behaviors should be investigated.

### 2. Identify Relevant Telemetry

The next step is identifying the logs required to test the hypothesis.

Depending on the scenario, relevant telemetry may include:

- Authentication events
- Endpoint process events
- Network connections
- Account changes
- Device logons
- Email activity
- Microsoft Entra ID audit events
- Microsoft Defender XDR telemetry

### 3. Develop the KQL Query

A KQL query is created to:

- Filter irrelevant activity
- Search for suspicious indicators
- Normalize important fields
- Aggregate related events
- Correlate activity across time
- Prioritize high-risk results
- Create an investigation timeline

### 4. Analyze the Results

Query results are reviewed for relevant entities and indicators, including:

- User accounts
- Devices
- IP addresses
- Geographic locations
- Applications
- Processes
- Command-line arguments
- Parent and child processes
- File hashes
- Authentication results
- Timestamps

### 5. Validate the Activity

Suspicious activity must be validated before escalation.

The investigator should consider:

- Whether the activity was expected
- Whether the account or device belongs to an administrator
- Whether the source IP address is trusted
- Whether the process is associated with approved software
- Whether similar events occurred on other devices
- Whether the behavior matches the established environment baseline
- Whether additional indicators support the hypothesis

### 6. Map to MITRE ATT&CK

Relevant activity is mapped to MITRE ATT&CK tactics and techniques to provide a standardized description of attacker behavior.

### 7. Recommend Response Actions

If the activity is confirmed or remains highly suspicious, the investigation includes response recommendations such as:

- Isolating the affected device
- Disabling or restricting the account
- Resetting credentials
- Revoking active sessions
- Blocking malicious indicators
- Collecting additional forensic evidence
- Reviewing related accounts and devices
- Creating or improving an analytics rule
- Increasing monitoring for similar behavior

---

## Threat Hunts Included

| Threat Hunt | Investigation Objective | Primary Data Source | MITRE ATT&CK |
|---|---|---|---|
| Impossible Travel | Identify sign-ins from geographically distant locations within an unrealistic time period | `SigninLogs` | T1078 |
| Password Spray | Identify authentication failures targeting multiple accounts from a common source | `SigninLogs` | T1110.003 |
| Encoded PowerShell | Detect suspicious PowerShell executions using encoded or obfuscated command-line parameters | `DeviceProcessEvents` | T1059.001, T1027 |
| Credential Dumping | Identify process activity potentially associated with credential dumping techniques | `DeviceProcessEvents`, `SecurityEvent` | T1003 |

> The exact tables and fields available depend on the connected data sources and the configuration of the security environment.

---

## Current Project Structure

```text
kql-threat-hunting/
│
├── README.md
├── credential-dumping.md
├── encoded-powershell.md
├── impossible-travel.md
└── password-spray.md
```

Additional threat hunts may be added as the portfolio develops.

---

## Identity Threat Hunting

Identity-focused investigations analyze authentication and account activity to identify potential compromise.

Examples include:

- Password spraying
- Impossible travel
- Suspicious sign-in locations
- Repeated authentication failures
- Abnormal account activity
- Privileged account usage
- Unusual application access

Relevant telemetry may include:

```kusto
SigninLogs
AADNonInteractiveUserSignInLogs
AuditLogs
IdentityLogonEvents
IdentityDirectoryEvents
```

---

## Endpoint Threat Hunting

Endpoint-focused investigations analyze process execution, logon events, files, registry changes, and network connections.

Examples include:

- Encoded PowerShell execution
- Credential dumping
- Suspicious parent-child process relationships
- LOLBins abuse
- Persistence mechanisms
- Unusual administrative tools
- Suspicious outbound connections

Relevant telemetry may include:

```kusto
DeviceProcessEvents
DeviceLogonEvents
DeviceFileEvents
DeviceRegistryEvents
DeviceNetworkEvents
DeviceEvents
SecurityEvent
```

---

## Example KQL Workflow

The following example demonstrates a simplified endpoint-hunting workflow:

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "-enc",
    "-encodedcommand",
    "FromBase64String"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### Query Purpose

This query searches for PowerShell activity containing parameters or functions commonly associated with encoded commands.

### Investigation Considerations

A match does not automatically confirm malicious activity.

The analyst should review:

- The complete command line
- The initiating process
- The user account
- The affected device
- Other activity around the same timestamp
- Network connections created by the process
- Whether the command was part of an approved administrative task

---

## KQL Techniques Demonstrated

The projects use KQL techniques such as:

### Filtering

```kusto
| where
```

Used to reduce the dataset to events relevant to the investigation.

### Field Selection

```kusto
| project
```

Used to display the fields most useful to the analyst.

### Aggregation

```kusto
| summarize
```

Used to group related events and identify patterns.

### Time-Based Analysis

```kusto
| bin(Timestamp, 15m)
```

Used to group activity into consistent time intervals.

### Entity Correlation

```kusto
| join
```

Used to combine related information from multiple data sources.

### Reusable Query Logic

```kusto
let SuspiciousActivity =
```

Used to define intermediate datasets and make more complex queries easier to understand.

### Result Prioritization

```kusto
| order by
```

Used to organize findings by time, count, severity, or another relevant field.

---

## MITRE ATT&CK Coverage

| MITRE ID | Technique | Portfolio Application |
|---|---|---|
| T1003 | OS Credential Dumping | Investigation of activity associated with credential access |
| T1027 | Obfuscated Files or Information | Identification of encoded or obfuscated commands |
| T1059.001 | PowerShell | Analysis of suspicious PowerShell execution |
| T1078 | Valid Accounts | Investigation of potentially compromised account activity |
| T1110.003 | Password Spraying | Detection of authentication attempts against multiple accounts |
| T1218 | Signed Binary Proxy Execution | Analysis of trusted Windows binaries potentially used for malicious execution |

---

## Structure of Each Threat Hunt

Each individual threat-hunting document should contain the following sections:

### Threat-Hunting Hypothesis

A clear statement describing the suspicious behavior being investigated.

### Threat Description

An explanation of the technique and its potential impact.

### Data Sources

The logs, tables, and important fields used in the investigation.

### MITRE ATT&CK Mapping

The associated tactic, technique, and sub-technique where applicable.

### KQL Query

The complete query used to investigate the activity.

### Query Explanation

A breakdown of the query logic and why each stage is included.

### Expected Results

A description of the activity that may be returned by the query.

### False-Positive Considerations

Examples of legitimate behavior that may trigger the query.

### Investigation Steps

Actions an analyst should perform to validate the findings.

### Response Recommendations

Potential containment, remediation, and monitoring improvements.

### Lessons Learned

Key technical and analytical takeaways from the investigation.

---

## False-Positive Management

Threat-hunting queries frequently identify behavior that can be both legitimate and malicious.

Potential false-positive sources include:

- Approved administrative scripts
- Software deployment systems
- Vulnerability scanners
- Penetration-testing activity
- Security validation exercises
- Service accounts
- Remote management tools
- VPN and proxy services
- Traveling employees
- Automated authentication processes

Queries should be tuned using environmental context and known-good activity.

Allowlisting should be carefully documented and should not suppress unrelated suspicious behavior.

---

## From Hunting Query to Detection Rule

A successful hunting query may eventually become a scheduled analytics rule.

Before converting a query into a detection, the following should be considered:

1. Does the query identify behavior that requires analyst review?
2. Is the required telemetry consistently available?
3. How frequently should the query run?
4. What time window should be analyzed?
5. Which entities should be included in the alert?
6. What legitimate activity may create false positives?
7. What severity should be assigned?
8. What investigation steps should accompany the alert?
9. Which MITRE ATT&CK techniques apply?
10. How will the rule be tested and tuned?

This process connects proactive threat hunting with detection engineering and SOC operations.

---

## Evidence and Screenshots

Where available, individual projects may include supporting evidence such as:

- KQL query screenshots
- Query result screenshots
- Microsoft Sentinel investigation views
- Microsoft Defender XDR telemetry
- Event timelines
- MITRE ATT&CK references
- Sanitized log examples

Sensitive information, user data, internal identifiers, and confidential organizational information should not be included.

---

## Skills Demonstrated

This section of the portfolio demonstrates practical experience in:

- Kusto Query Language
- Microsoft Sentinel
- Microsoft Defender XDR
- Threat-hunting methodology
- Identity threat investigation
- Endpoint telemetry analysis
- Authentication log analysis
- Event correlation
- Security monitoring
- Incident investigation
- Detection engineering
- False-positive evaluation
- MITRE ATT&CK mapping
- Technical documentation

---

## Limitations

These projects are based on lab environments, simulations, and portfolio scenarios.

Important limitations include:

- Table availability may differ between environments.
- Field names may vary between Microsoft Sentinel and Defender XDR.
- Data retention periods may affect investigation results.
- Queries may require tuning based on organizational baselines.
- Some sample queries may not return results without the required data connectors.
- A query match should not be treated as proof of malicious activity without validation.

---

## Future Improvements

Planned areas of development include:

- Multi-table correlation queries
- Defender XDR Advanced Hunting
- Threat intelligence indicator correlation
- Persistence detection
- Lateral movement hunting
- Suspicious OAuth application activity
- Privileged identity monitoring
- Microsoft Sentinel analytics rules
- Investigation workbooks
- Security automation and response workflows

---

## Author

**Eros Marin Morales**

Microsoft-certified cybersecurity professional developing practical experience in:

- Security Operations
- Microsoft Sentinel
- Microsoft Defender XDR
- KQL
- Threat Hunting
- Incident Response
- Detection Engineering

### Certifications

- Microsoft Certified: Security Operations Analyst Associate, SC-200
- Microsoft Certified: Security, Compliance, and Identity Fundamentals, SC-900

---

## Disclaimer

All queries, investigations, and scenarios in this section are intended for educational, defensive-security, and professional portfolio purposes.

The projects are based on lab environments, simulated scenarios, and publicly documented cybersecurity techniques. No unauthorized testing was performed.

Detection logic should be validated and tuned before being used in a production environment.
