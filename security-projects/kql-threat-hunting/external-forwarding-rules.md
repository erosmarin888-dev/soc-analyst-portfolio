# External Forwarding Rule Detection

## Objective

Identify mailbox forwarding rules that automatically redirect emails to external domains. Attackers commonly create forwarding rules after compromising an account to maintain access to sensitive communications.

## MITRE ATT&CK

- T1114.003 - Email Collection: Email Forwarding Rule

## KQL Query

```kusto
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    Parameters
| order by TimeGenerated desc
```

## Data Source

- OfficeActivity
- Microsoft 365
- Exchange Online

## Threat Scenario

An attacker gains access to a mailbox and creates a forwarding rule that automatically sends incoming emails to an external address. This allows the attacker to monitor communications and potentially conduct Business Email Compromise (BEC) attacks.

## Analyst Investigation Steps

1. Review the forwarding destination.
2. Determine whether the destination belongs to the organization.
3. Verify if the mailbox owner authorized the rule.
4. Review recent sign-in activity.
5. Check for other indicators of compromise.
6. Remove unauthorized forwarding rules.

## Expected Findings

- Unauthorized forwarding rules
- Account compromise
- Business Email Compromise (BEC)
- Insider threat activity

## Severity

High

## MITRE Mapping

| Tactic | Technique |
|----------|----------|
| Collection | T1114.003 |
| Persistence | T1114.003 |

## Remediation

- Disable unauthorized forwarding rules.
- Reset user credentials.
- Force MFA re-registration if necessary.
- Review affected communications.
- Monitor for future mailbox rule creation.
```
