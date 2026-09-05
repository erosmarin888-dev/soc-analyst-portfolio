# T1566 - Phishing Detection

## Description

Detect suspicious email activity that may indicate phishing attempts targeting users within the organization.

## MITRE ATT&CK

- T1566 - Phishing

## Severity

High

## Data Source

- Microsoft Defender for Office 365
- EmailEvents

## Detection Logic

Identify emails originating from external senders that contain suspicious keywords commonly associated with phishing campaigns.

## KQL Query

```kusto
EmailEvents
| where SenderFromAddress !endswith "@company.com"
| where Subject has_any (
    "urgent",
    "verify",
    "password",
    "account",
    "invoice",
    "payment",
    "security alert",
    "action required"
)
| project
    Timestamp,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    DeliveryAction
| order by Timestamp desc
```

## Investigation Steps

1. Review the sender's email address.
2. Analyze the message subject and content.
3. Check for suspicious URLs or attachments.
4. Verify whether users interacted with the email.
5. Search for additional recipients.
6. Determine whether malicious payloads were delivered.

## Expected Findings

- Credential harvesting attempts
- Malware delivery campaigns
- Business Email Compromise (BEC)
- Social engineering attacks

## False Positives

- Legitimate vendor communications
- Security awareness training emails
- Automated notifications

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Initial Access | T1566 |

## Response Actions

- Quarantine malicious emails.
- Block sender domains.
- Investigate affected users.
- Review endpoint activity.
- Reset credentials if compromise is confirmed.

## References

- MITRE ATT&CK T1566 - Phishing
- Microsoft Defender for Office 365
```
