# Security Detections

This folder contains detection engineering projects designed to identify suspicious and malicious activity using Microsoft security technologies and Kusto Query Language (KQL).

The detections are based on common attack techniques observed in enterprise environments and are mapped to the MITRE ATT&CK framework whenever applicable.

---

# Purpose

The goal of these projects is to demonstrate practical detection engineering skills used by Security Operations Center (SOC) teams to identify, investigate, and respond to threats.

These detections focus on:

- Threat Detection
- Security Monitoring
- Attack Identification
- Detection Engineering
- SIEM Content Development
- Alert Logic Development
- MITRE ATT&CK Mapping

---

# Detection Coverage

## Identity-Based Detections

- Password Spray Detection
- Account Manipulation
- Suspicious Authentication Activity
- Privileged Account Monitoring

## Endpoint-Based Detections

- Encoded PowerShell Commands
- Credential Dumping Activity
- LOLBins Abuse
- Suspicious Process Execution
- Defense Evasion Techniques

## Email-Based Detections

- Phishing Activity
- Malicious Attachments
- External Forwarding Rules
- Suspicious Mailbox Operations

---

# MITRE ATT&CK Coverage

| MITRE ID | Technique |
|----------|-----------|
| T1027 | Obfuscated Files or Information |
| T1003 | OS Credential Dumping |
| T1059.001 | PowerShell |
| T1098 | Account Manipulation |
| T1110.003 | Password Spraying |
| T1218 | Signed Binary Proxy Execution |
| T1566 | Phishing |
| T1566.001 | Spearphishing Attachment |
| T1114 | Email Collection |

---

# Detection Methodology

Each project follows a structured approach:

### 1. Detection Objective

Description of the attack technique or suspicious behavior.

### 2. Threat Description

Explanation of how the activity could impact an environment.

### 3. Relevant Telemetry

Identification of data sources and log tables.

### 4. Detection Logic

KQL query or detection rule used to identify the activity.

### 5. MITRE ATT&CK Mapping

Associated tactics and techniques.

### 6. Expected Results

Examples of findings and indicators.

### 7. False Positive Considerations

Known legitimate activities that may trigger the detection.

### 8. Response Recommendations

Suggested analyst actions and remediation steps.

---

# Technologies Used

- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- Microsoft Defender for Office 365
- Microsoft Entra ID
- Kusto Query Language (KQL)

---

# Skills Demonstrated

- Detection Engineering
- Security Monitoring
- KQL Development
- SIEM Content Creation
- Threat Detection
- Log Analysis
- Security Operations
- Incident Response Support
- MITRE ATT&CK Mapping
- Alert Logic Development

---

# Example Repository Structure

```text
Security-Detections/
│
├── T1027-EncodedCommand.md
├── T1098-AccountManipulation.md
├── T1218-LOLBinsAbuse.md
├── T1566-Phishing.md
├── Password-Spray-Analytics-Rule.md
├── External-Forwarding-Rules.md
└── Malicious-Attachments.md
```

---

# Learning Objectives

This project was created to strengthen practical experience in:

- Detection Engineering
- KQL Query Development
- Threat Detection
- SOC Operations
- Security Investigations
- Attack Analysis

---

# Author

**Eros Marin Morales**

Cybersecurity professional focused on:

- Microsoft Sentinel
- Defender XDR
- Threat Hunting
- Detection Engineering
- Incident Response
- Security Operations

### Certifications

- Microsoft Certified: Security Operations Analyst Associate (SC-200)
- Microsoft Certified: Security, Compliance, and Identity Fundamentals (SC-900)

---

# Disclaimer

These detections are designed for educational, research, and professional portfolio purposes.

Detection logic may require tuning based on organizational requirements, log availability, and environmental baselines before being deployed in production environments.

All projects are based on defensive security concepts and authorized lab activities.
