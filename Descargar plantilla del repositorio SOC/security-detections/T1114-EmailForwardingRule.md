# T1114 - Email Forwarding Rule Detection

## Description

Detect the creation or modification of mailbox forwarding rules that automatically redirect emails to external recipients. Attackers frequently abuse forwarding rules after compromising a mailbox to collect sensitive information and maintain visibility into communications.

## MITRE ATT&CK

- T1114.003 - Email Collection: Email Forwarding Rule

## Severity

High

## Data Source

- Microsoft 365
- OfficeActivity

## Detection Logic

Identify newly created or modified inbox rules that contain forwarding or redirection actions.

## KQL Query

```kusto
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any (
    "ForwardTo",
    "RedirectTo",
    "ForwardAsAttachmentTo"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    Parameters
| order by TimeGenerated desc
```

## Investigation Steps

1. Review the forwarding destination.
2. Determine whether the destination is external.
3. Verify whether the user authorized the rule.
4. Investigate recent sign-in activity.
5. Review mailbox audit logs.
6. Search for additional indicators of compromise.

## Expected Findings

- Unauthorized forwarding rules
- Business Email Compromise (BEC)
- Account takeover activity
- Email collection attempts
- Insider threat activity

## False Positives

- Legitimate mailbox delegation
- Authorized forwarding configurations
- Shared mailbox administration

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Collection | T1114.003 |
| Persistence | T1114.003 |

## Response Actions

- Disable unauthorized forwarding rules.
- Review mailbox permissions.
- Reset affected credentials.
- Revoke active sessions.
- Enforce MFA and Conditional Access policies.

## References

- MITRE ATT&CK T1114.003 - Email Collection: Email Forwarding Rule
- Microsoft Exchange Online Auditing
```
