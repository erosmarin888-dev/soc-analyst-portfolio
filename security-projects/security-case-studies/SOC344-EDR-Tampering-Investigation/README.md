# SOC344 - EDR Tampering Attempt via EDR-Freeze

## Overview

This case study documents the investigation of a security alert involving suspected Endpoint Detection and Response (EDR) tampering activity.

The objective of the investigation was to determine whether the detected behavior represented malicious activity, analyze the associated endpoint and process activity, assess the scope of the incident, and determine the appropriate containment response.

The investigation was completed in the LetsDefend SOC simulation environment and resulted in a **True Positive** determination.

---

## Investigation Summary

| Category | Details |
|---|---|
| Platform | LetsDefend |
| Investigation | SOC344 |
| Alert | EDR Tampering Attempt via EDR-Freeze |
| Category | Defense Evasion / Malware Investigation |
| Affected Host | WS-Prod-02 |
| Internal IP | 172.16.20.69 |
| Suspicious File | EDR-Freeze_1.0.exe |
| Operating System | Windows |
| Data Sources | Endpoint Security, Log Management, Windows Event Viewer, Sysmon |
| Verdict | True Positive |
| Containment | Endpoint isolation recommended |
| Scope | Single affected endpoint identified |

---

# 1. Alert Triage

The investigation began by reviewing the SOC alert and establishing the basic context of the incident.

The alert indicated potential EDR tampering behavior involving **EDR-Freeze**, requiring investigation of the endpoint, associated processes, and related system activity.

evidence/01-soc344-alert-overview.png

The initial triage established that the behavior required further investigation rather than being immediately dismissed as benign activity.

---

# 2. Suspicious Executable Investigation

Endpoint telemetry identified the executable:

`EDR-Freeze_1.0.exe`

The suspicious executable was associated with the affected Windows endpoint and became a primary artifact for the investigation.

evidence/02-edr-freeze-suspicious-executable.png

The executable was investigated alongside surrounding process activity to determine whether the behavior was consistent with an attempt to interfere with endpoint security controls.

---

# 3. Network and Log Investigation

Log Management was used to investigate activity associated with the affected endpoint.

This phase focused on correlating activity around the alert with additional endpoint and network telemetry.

evidence/03-endpoint-network-investigation.png

Rather than relying only on the original security alert, the investigation used multiple telemetry sources to determine the broader context of the activity.

---

# 4. Process Investigation

Process activity associated with `EDR-Freeze_1.0.exe` was examined to understand how the executable interacted with other processes on the endpoint.

evidence/04-edr-freeze-process-investigation.png

Process relationships are particularly important during defense evasion investigations because suspicious tools may interact with legitimate Windows processes or security components.

---

# 5. Process Correlation

Further process analysis identified activity involving:

`WerFaultSecure.exe`

The process relationship was correlated with `EDR-Freeze_1.0.exe`.

evidence/05-werfaultsecure-process-correlation.png

Analyzing the parent-child process relationship provided additional context regarding the behavior observed on the endpoint.

---

# 6. Sysmon Investigation

Windows Event Viewer and Sysmon telemetry were used to continue the endpoint investigation.

Sysmon **Event ID 1 (Process Create)** provided process creation telemetry that could be examined alongside the other evidence collected during the incident.

evidence/06-sysmon-process-creation-analysis.png

This demonstrates the value of host-based telemetry when investigating suspicious process execution and defense evasion activity.

---

# 7. Microsoft Defender Process Evidence

Additional Sysmon telemetry showed:

`MsMpEng.exe`

The executable path visible in the telemetry identifies the process as part of the Microsoft Defender platform.

evidence/07-defender-msmpeng-process-evidence.png

This information was important when examining the endpoint's security-related process activity during the investigation.

---

# 8. Defense Evasion Analysis

Based on the collected endpoint evidence and the context of the alert, the investigation focused on behavior involving modification or interference with security controls.

evidence/08-defense-evasion-classification.png

The behavior was evaluated as a **Defense Evasion** scenario rather than ordinary endpoint activity.

A relevant MITRE ATT&CK category for this type of investigation is:

**T1562 - Impair Defenses**

This technique covers adversary behavior intended to interfere with security tools or defensive capabilities.

---

# 9. Scope and Containment

After reviewing the available telemetry, the investigation identified `WS-Prod-02` as the affected endpoint.

The final incident assessment determined that the endpoint should be isolated to help prevent additional malicious activity.

The investigation did not identify additional affected devices within the scope of the lab evidence.

evidence/09-incident-verdict-and-containment.png

The final classification was:

**True Positive**

The investigation was completed with a **30/30 (100% success rate)**.

---

# Incident Timeline

The investigation followed the following analytical workflow:

1. Reviewed the initial SOC alert.
2. Identified the affected Windows endpoint.
3. Investigated `EDR-Freeze_1.0.exe`.
4. Reviewed associated endpoint and log telemetry.
5. Investigated related process activity.
6. Correlated `WerFaultSecure.exe` with the suspicious activity.
7. Reviewed Windows Sysmon Process Creation events.
8. Examined Microsoft Defender-related process telemetry.
9. Evaluated the behavior as Defense Evasion activity.
10. Determined the scope of the incident.
11. Recommended isolation of the compromised endpoint.
12. Classified the alert as a True Positive.

---

# Key Findings

- Suspicious activity involving `EDR-Freeze_1.0.exe` was investigated.
- The affected endpoint was identified as `WS-Prod-02`.
- The endpoint IP was `172.16.20.69`.
- Process relationships were examined during the investigation.
- `WerFaultSecure.exe` appeared in the process investigation.
- Sysmon Process Creation telemetry was analyzed.
- Microsoft Defender process telemetry involving `MsMpEng.exe` was reviewed.
- The activity was investigated as Defense Evasion behavior.
- Only one affected endpoint was identified within the available evidence.
- Endpoint isolation was recommended.
- The alert was ultimately classified as a **True Positive**.

---

# MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Impair Defenses | T1562 | Investigation involved suspected interference with endpoint defensive capabilities |

---

# Tools and Technologies

- LetsDefend
- Windows Event Viewer
- Sysmon
- Endpoint Security telemetry
- Log Management
- Windows process analysis
- Microsoft Defender telemetry
- MITRE ATT&CK

---

# Skills Demonstrated

This investigation demonstrates hands-on experience with:

- SOC alert triage
- Endpoint investigation
- Defense evasion analysis
- Windows process analysis
- Parent-child process correlation
- Sysmon log analysis
- Windows Event Viewer
- Security telemetry correlation
- IOC investigation
- Incident scoping
- True Positive / False Positive classification
- Endpoint containment decision-making
- MITRE ATT&CK mapping
- Incident documentation

---

# Analyst Conclusion

The investigation confirmed suspicious activity consistent with an attempt to interfere with endpoint security controls.

Correlation between the original alert, endpoint telemetry, process activity, and Sysmon events provided sufficient context to classify the incident as a **True Positive**.

`WS-Prod-02` was identified as the affected endpoint, and endpoint isolation was determined to be the appropriate containment action.

The case demonstrates an investigation workflow in which an initial SOC alert was validated through multiple telemetry sources before making a final incident classification and containment decision.

---

## Disclaimer

This case study was completed in a simulated SOC environment provided by LetsDefend. All systems, indicators, and investigation artifacts shown here are associated with the training scenario.

The purpose of this repository is to demonstrate practical SOC analysis, investigation methodology, technical reasoning, and incident-response documentation.
