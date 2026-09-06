# Phishing Investigation Case Study

> Portfolio Disclaimer: This is a simulated SOC investigation created for educational and portfolio purposes. All indicators, accounts, domains, and data are fictional.

## Executive Summary

A user reported a suspicious email claiming to be from the IT department requesting immediate password verification.

The email contained a hyperlink directing users to a fraudulent website designed to harvest credentials.

A phishing investigation was initiated to determine:

- Whether users interacted with the email.
- Whether credentials were compromised.
- Whether additional users received the message.
- Whether the malicious domain posed an ongoing threat.

## Alert Information

| Field | Value |
|---------|---------|
| Alert Name | Potential Phishing Campaign |
| Severity | High |
| Status | Investigated |
| Detection Source | User Report / Email Security Controls |
| Platform | Microsoft Defender for Office 365 |
| MITRE ATT&CK | T1566.002 |
| Environment | Simulated Lab |

---

## Incident Description

A user reported receiving an email with the following characteristics:

- Urgent tone
- Credential verification request
- Suspicious hyperlink
- External sender
- Request for immediate action

Subject Example:

```text
Your Password Will Expire Today
```

Sender Example:

```text
security-team@fake-company-support.com
```

---

## Objectives

The objectives of the investigation were:

- Validate phishing indicators.
- Analyze sender infrastructure.
- Identify affected recipients.
- Review user interactions.
- Assess potential compromise.
- Recommend containment actions.

---

## Initial Indicators of Compromise

### Suspicious Sender

The sender used a domain mimicking a trusted organization.

Example:

```text
microsoft-support-security.com
```

### Suspicious URL

The embedded URL redirected users to a credential harvesting page.

Example:

```text
https://secure-password-reset-example.com
```

### Social Engineering Tactics

The email attempted to create urgency by:

- Threatening account suspension
- Requesting credential verification
- Claiming immediate action was required

---

## Investigation Process

### Step 1 - Review Email Headers

The email headers were reviewed to identify:

- Sender IP
- Reply-To address
- SPF results
- DKIM validation
- DMARC results

Key questions:

- Was the sender legitimate?
- Did the domain pass authentication checks?
- Was spoofing detected?

---

### Step 2 - Analyze URLs

The embedded hyperlinks were analyzed for:

- Domain reputation
- Domain age
- URL redirections
- SSL certificate information
- Threat intelligence matches

---

### Step 3 - Review Recipient Impact

Investigators reviewed:

- Number of recipients
- Click activity
- Email forwarding activity
- Credential submission indicators

---

### Step 4 - Review Authentication Activity

The accounts that interacted with the email were investigated.

Focus areas included:

- Successful sign-ins
- Geographic anomalies
- MFA events
- Risky sign-ins

---

### Step 5 - Endpoint Review

Endpoints associated with users who clicked links were reviewed for:

- Malware execution
- Browser downloads
- Suspicious processes
- Persistence mechanisms

---

## Threat Hunting Activities

### Search For Related Emails

```kql
EmailEvents
| where Subject contains "Password"
| project Timestamp,
          RecipientEmailAddress,
          SenderFromAddress,
          Subject
```

---

### Search For User Click Activity

```kql
UrlClickEvents
| project Timestamp,
          AccountUpn,
          Url,
          ActionType
```

---

### Search For Related Alerts

```kql
AlertInfo
| where Title contains "Phishing"
```

---

## Findings

The investigation identified:

- External sender infrastructure.
- Suspicious hyperlink activity.
- Multiple recipients.
- Social engineering indicators.
- Credential harvesting behavior.

The activity was determined to be consistent with a phishing attempt.

---

## Root Cause Assessment

The primary objective of the threat actor appeared to be:

- Credential theft
- Unauthorized access
- Initial access into cloud services

The phishing email leveraged urgency and impersonation techniques to increase success rates.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|------------|------------|------------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |

---

## Potential Business Impact

Successful compromise could result in:

- Unauthorized mailbox access
- Account takeover
- Data exposure
- Business email compromise
- Lateral movement opportunities

---

## Response Actions

Upon confirmation:

1. Block sender domain.
2. Remove malicious emails.
3. Block malicious URLs.
4. Reset compromised accounts.
5. Revoke active sessions.
6. Review mailbox activity.
7. Validate MFA enforcement.
8. Notify affected users.

---

## Detection Improvement Opportunities

Potential improvements include:

- Enhanced domain reputation filtering.
- Automated URL detonation.
- User awareness training.
- Improved email authentication policies.
- Threat intelligence enrichment.

---

## Final Classification

Classification: Confirmed Phishing Attempt

Confidence Level: High

Evidence strongly supported a phishing campaign designed to harvest user credentials.

---

## Lessons Learned

This case demonstrates the importance of:

- Email threat analysis.
- IOC identification.
- URL reputation analysis.
- Authentication investigations.
- User awareness.
- Incident documentation.
- Threat hunting techniques.

---

## Skills Demonstrated

- Phishing Analysis
- Microsoft Defender for Office 365
- IOC Investigation
- Threat Hunting
- KQL
- Email Security
- MITRE ATT&CK Mapping
- Incident Response
- Security Documentation

---

## Author

Eros Marin Morales

SOC Analyst Portfolio Project
