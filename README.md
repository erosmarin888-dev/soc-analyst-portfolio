# SOC Analyst Portfolio

https://img.shields.io/badge/SOC-Analyst-blue
https://img.shields.io/badge/Microsoft-Sentinel-0078D4
https://img.shields.io/badge/Microsoft-Defender_XDR-5C2D91
https://img.shields.io/badge/KQL-Threat_Hunting-orange
https://img.shields.io/badge/MITRE-ATT%26CK-red
https://img.shields.io/badge/SC--200-Certified-green
https://img.shields.io/badge/SC--900-Certified-brightgreen

---

# Welcome

Welcome to my cybersecurity portfolio.

This repository demonstrates practical Security Operations Center (SOC) skills through incident investigations, detection engineering projects, and threat hunting exercises using Microsoft security technologies.

The objective of this repository is to showcase real-world cybersecurity workflows commonly performed by SOC Analysts and Security Operations teams.

---

# About Me

Hello, I'm **Eros Marin Morales**.

I am a Technical Support Engineer at Wipro supporting Microsoft environments and currently transitioning into a Cybersecurity Analyst role.

I have more than two years of experience supporting enterprise environments while developing hands-on cybersecurity skills focused on:

- Microsoft Sentinel
- Microsoft Defender XDR
- Threat Hunting
- Incident Response
- Detection Engineering
- Kusto Query Language (KQL)
- Security Monitoring
- Identity Security

### Certifications

- Microsoft SC-900 Security, Compliance, and Identity Fundamentals
- Microsoft SC-200 Security Operations Analyst

### Languages

- Spanish
- English
- Portuguese

---

# Repository Structure

```text
SOC-Portfolio
│
├── Incident-Response-Cases
│
├── Security-Detections
│
├── Threat-Hunting
│
└── README.md
```

---

# Incident Response Cases

These investigations simulate common security incidents handled by a SOC Analyst.

| Investigation | Description |
|--------------|-------------|
| Impossible Travel | Suspicious sign-ins from distant geographic locations |
| Password Spray | Brute-force authentication activity |
| External Forwarding Rule | Potential email data exfiltration |
| Phishing Investigation | User targeted by phishing campaign |
| Malicious Attachment | Detection and analysis of malicious email attachments |
| Account Manipulation | Unauthorized account modifications |
| PowerShell Abuse | Suspicious PowerShell execution |
| Privilege Escalation | Unauthorized privilege assignment |
| Business Email Compromise | Investigation of compromised mailbox activity |
| MFA Fatigue | Multiple MFA prompts targeting a user |

### Investigation Methodology

Each incident follows a structured workflow:

1. Incident Summary
2. Alert Details
3. Investigation Process
4. Findings
5. Root Cause Analysis
6. MITRE ATT&CK Mapping
7. Containment Actions
8. Recommendations
9. Lessons Learned

---

# Security Detections

Security detections were created using real-world SOC concepts and MITRE ATT&CK mappings.

| Detection | MITRE ATT&CK |
|------------|--------------|
| T1027 Encoded PowerShell Commands | Obfuscated Files or Information |
| T1098 Account Manipulation | Account Manipulation |
| T1566 Phishing Detection | Phishing |
| T1218 LOLBins Abuse | Signed Binary Proxy Execution |
| Password Spray Analytics Rule | Brute Force |
| External Forwarding Rules Detection | Email Collection |
| 
