# KQL Threat Hunting

A collection of threat hunting queries developed using Kusto Query Language (KQL) for Microsoft Sentinel and Microsoft Defender XDR.

This repository demonstrates practical threat hunting techniques used to detect suspicious, malicious, and abnormal activity within enterprise environments.

---

# About This Repository

The goal of this project is to showcase hands-on threat hunting skills through detection logic, log analysis, and MITRE ATT&CK-aligned investigations.

Each hunt includes:

- Objective
- Threat Description
- MITRE ATT&CK Mapping
- KQL Query
- Query Explanation
- Investigation Guidance
- Expected Results

---

# Technologies

- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Entra ID
- Kusto Query Language (KQL)
- MITRE ATT&CK

---

# Threat Hunts Included

## Identity-Based Threats

- Impossible Travel Detection
- Password Spray Activity
- Suspicious Sign-in Locations
- Privileged Account Monitoring
- Enterprise Application Consent Abuse

## Endpoint-Based Threats

- Encoded PowerShell Execution
- Credential Dumping Activity
- LOLBins Abuse
- Process Injection Indicators
- Persistence Mechanisms

## Email-Based Threats

- External Forwarding Rules
- Malicious Attachments
- Phishing Activity
- Suspicious Mailbox Operations

---

# MITRE ATT&CK Coverage

| MITRE ID | Technique |
|----------|-----------|
| T1027 | Obfuscated Files or Information |
| T1059.001 | PowerShell |
| T1003 | OS Credential Dumping |
| T1098 | Account Manipulation |
| T1110.003 | Password Spraying |
| T1218 | Signed Binary Proxy Execution |
| T1566 | Phishing |
| T1114 | Email Collection |

---

# Example Workflow

1. Identify suspicious activity.
2. Develop a hunting hypothesis.
3. Create and optimize KQL queries.
4. Investigate findings.
5. Correlate evidence.
6. Map activity to MITRE ATT&CK.
7. Document results.

---

# Skills Demonstrated

- Threat Hunting
- KQL Development
- Log Analysis
- Security Monitoring
- Detection Engineering
- Microsoft Sentinel
- Defender XDR
- Incident Investigation
- MITRE ATT&CK Mapping

---

# Learning Objectives

This repository was created to strengthen practical experience with:

- KQL Query Development
- Threat Detection
- Hunting Methodologies
- Security Operations
- Detection Engineering
- Security Investigations

---

# Disclaimer

All threat hunting examples are intended for educational, research, and professional portfolio purposes.

Examples are based on lab environments, publicly documented attack techniques, and defensive security practices.

No unauthorized testing or malicious activities were performed.

---

## About Me

**Eros Marin Morales**

- SC-200 Security Operations Analyst
- SC-900 Security, Compliance, and Identity Fundamentals
- Technical Support Engineer
- Aspiring SOC Analyst

### Areas of Interest

- Microsoft Sentinel
- Defender XDR
- Threat Hunting
- Detection Engineering
- Incident Response
- Cloud Security

---

⭐ Thank you for visiting my KQL Threat Hunting repository.
