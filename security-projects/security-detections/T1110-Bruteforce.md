# T1110 - Brute Force Detection

## MITRE ATT&CK

| Technique | ID |
|------------|------------|
| Brute Force | T1110 |

---

## Objective

Detect potential brute-force attacks by identifying a high number of failed authentication attempts against one or multiple user accounts within a short period of time.

---

## Detection Logic

This detection looks for:

- Multiple failed sign-in attempts
- Repeated authentication failures
- One source IP targeting many accounts
- Excessive authentication volume in a short timeframe

---

## Microsoft Sentinel KQL Query

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count(),
            TargetedAccounts=dcount(UserPrincipalName)
            by IPAddress
| where FailedAttempts > 20
| where TargetedAccounts > 5
| sort by FailedAttempts desc
```

---

## Investigation Steps

1. Identify the source IP address.
2. Review the targeted user accounts.
3. Determine if any login attempts succeeded.
4. Check geographic location of the source IP.
5. Review Defender XDR alerts for related activity.
6. Verify whether MFA challenges occurred.
7. Determine if account lockouts were triggered.

---

## Potential Impact

- Credential compromise
- Unauthorized access
- Lateral movement
- Privilege escalation
- Business Email Compromise (BEC)

---

## False Positives

Potential legitimate causes include:

- Users repeatedly entering incorrect passwords
- Password expiration events
- Automated service accounts
- Authentication testing activities
- VPN authentication issues

---

## Recommended Response

### Containment

- Block malicious source IPs
- Lock affected accounts
- Force password resets

### Recovery

- Review successful authentications
- Re-enable accounts if necessary
- Validate MFA registration

---

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |
| T1110.003 | Password Spraying |
| T1078 | Valid Accounts |

---

## Author Notes

This detection was developed as part of a SOC Analyst professional portfolio using Microsoft Sentinel and Microsoft Entra ID authentication telemetry.
