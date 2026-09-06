# Impossible Travel Investigation Case Study

> Portfolio Disclaimer: This is a simulated SOC investigation created for educational and portfolio purposes. All data is fictional and intended to demonstrate security analysis skills.

## Executive Summary

A Microsoft Sentinel alert identified a user account authenticating from two geographically distant locations within a time frame that would be impossible for legitimate travel.

The activity was investigated to determine if the authentication events represented:

- Credential compromise
- VPN usage
- Shared accounts
- Cloud service activity
- False positive behavior

## Alert Information

| Field | Value |
|---------|---------|
| Alert Name | Impossible Travel Activity |
| Severity | High |
| Status | Investigated |
| Data Source | Microsoft Entra ID |
| SIEM Platform | Microsoft Sentinel |
| MITRE ATT&CK | T1078 - Valid Accounts |
| Environment | Simulated Lab |

## Objective

The objectives of this investigation were:

- Validate the alert.
- Review authentication locations.
- Determine whether account compromise occurred.
- Investigate risk indicators.
- Identify suspicious cloud activity.
- Recommend response actions.

---

## Initial Alert Details

The alert identified successful sign-ins from locations separated by thousands of kilometers within a short period.

Example:

| Timestamp | Country |
|------------|------------|
| 08:00 AM | Costa Rica |
| 08:35 AM | Germany |

Based on normal travel limitations, the activity was considered suspicious and required investigation.

---

## Investigation Process

### Step 1 - Validate Sign-In Activity

Reviewed sign-in logs for:

- User account
- Source IP addresses
- Authentication status
- Device information
- Application used

### Step 2 - Review Locations

Analyzed:

- Geographic location
- ISP information
- VPN indicators
- Corporate network usage

Questions considered:

- Was a VPN in use?
- Was a cloud service generating tokens?
- Was the user traveling?

### Step 3 - Review Successful Authenticity

Validated:

- MFA completion
- Conditional Access results
- Risky sign-ins
- Identity Protection alerts

---

## Detection Logic

Example KQL used during investigation:

```kql
SigninLogs
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ResultType
| order by TimeGenerated desc
```

---

## Threat Hunting Activities

Additional review included:

### Authentication History

```kql
SigninLogs
| where UserPrincipalName == "user@contoso.com"
| order by TimeGenerated desc
```

### Risky Sign-ins

```kql
AADUserRiskEvents
| project
    UserPrincipalName,
    RiskLevel,
    RiskEventType,
    TimeGenerated
```

### MFA Review

```kql
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
```

---

## Findings

The investigation identified:

- Multiple successful authentications.
- Geographic inconsistencies.
- Unusual source IP addresses.
- Elevated account risk indicators.

No evidence suggested legitimate travel during the alert timeframe.

The activity was classified as potentially malicious until additional validation could be completed.

---

## Root Cause Assessment

Possible causes included:

### Potential Account Compromise

An attacker may have obtained valid credentials and successfully authenticated from a foreign location.

### VPN Usage

A VPN service could have altered the apparent geographic source.

### Session Token Abuse

Previously issued authentication tokens may have been reused from another location.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|------------|------------|------------|
| Defense Evasion | Valid Accounts | T1078 |
| Initial Access | Valid Accounts | T1078 |

---

## Potential False Positives

The following scenarios may generate Impossible Travel alerts:

- VPN usage
- Corporate proxies
- Cloud application token activity
- Mobile carrier routing
- International travel
- Shared service accounts

---

## Recommended Response Actions

If malicious activity is confirmed:

1. Reset account password.
2. Revoke active sessions.
3. Force MFA re-registration.
4. Review mailbox activity.
5. Investigate endpoint alerts.
6. Review OAuth grants.
7. Validate Conditional Access policies.
8. Escalate to Incident Response.

---

## Detection Improvement Opportunities

Potential enhancements include:

- Correlation with Risky Sign-ins.
- Integration with threat intelligence feeds.
- Detection tuning for known VPN providers.
- Prioritization of privileged accounts.
- Correlation with Defender XDR alerts.

---

## Final Classification

Classification: Suspicious Activity Requiring Investigation

Confidence Level: Medium

The evidence suggested possible account compromise but additional context was required before confirming malicious activity.

---

## Lessons Learned

This case demonstrates the importance of:

- Entra ID sign-in analysis.
- Authentication investigations.
- Cloud identity monitoring.
- Risk-based detection.
- MFA validation.
- Identity threat hunting.
- Security documentation.

---

## Skills Demonstrated

- Microsoft Sentinel
- Microsoft Entra ID
- KQL
- Threat Hunting
- Incident Analysis
- Cloud Security Monitoring
- Identity Security
- MITRE ATT&CK Mapping
- Security Documentation

---

## Author

Eros Marin Morales

SOC Analyst Portfolio Project
