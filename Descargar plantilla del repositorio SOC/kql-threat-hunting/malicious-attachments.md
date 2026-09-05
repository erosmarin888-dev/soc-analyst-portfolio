# Malicious Attachment Detection

## Objective

Identify emails containing potentially malicious file attachments commonly used in phishing and malware delivery campaigns.

## MITRE ATT&CK

- T1566.001 - Phishing: Spearphishing Attachment

## KQL Query

```kusto
EmailAttachmentInfo
| where FileType in~ (
    "exe",
    "dll",
    "js",
    "vbs",
    "iso",
    "img",
    "lnk",
    "bat",
    "cmd"
)
| project
    Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    FileName,
    FileType,
    FileSize
| order by Timestamp desc
```

## Data Source

- Microsoft Defender for Office 365
- EmailAttachmentInfo

## Threat Scenario

An attacker delivers malware through a phishing email containing a malicious attachment. When the recipient opens the file, malicious code is executed, potentially resulting in malware infection, credential theft, or unauthorized access.

## Analyst Investigation Steps

1. Review the attachment name and type.
2. Verify sender legitimacy.
3. Analyze the attachment in a sandbox environment.
4. Check whether recipients interacted with the file.
5. Investigate endpoint activity following delivery.
6. Search for additional recipients across the organization.

## Expected Findings

- Phishing campaigns
- Malware delivery attempts
- Suspicious executable attachments
- Social engineering attacks

## Severity

Medium-High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Initial Access | T1566.001 |

## Remediation

- Quarantine malicious emails.
- Block malicious senders and domains.
- Conduct endpoint investigation.
- Reset compromised credentials if necessary.
- Educate affected users regarding phishing threats.
```
