# Cloud Privilege Escalation Investigation Case Study

> **Portfolio Disclaimer:** This is a simulated SOC investigation created for educational and portfolio purposes. All accounts, devices, IP addresses, applications, role assignments, timestamps, and findings are fictional. No production or confidential information is included.

## Executive Summary

Microsoft Sentinel generated a high-severity alert after detecting an unexpected privileged role assignment in Microsoft Entra ID.

A standard user account was assigned an administrative cloud role without a documented business justification. The initiating account also showed unusual authentication activity shortly before the role assignment.

The investigation was initiated to:

- Validate the privileged role assignment.
- Identify the account that initiated the change.
- Determine whether the assignment was authorized.
- Review authentication activity associated with both accounts.
- Identify additional administrative changes.
- Determine the potential blast radius.
- Remove unauthorized access.
- Recommend containment, remediation, and monitoring actions.

## Alert Information

| Field | Value |
|---|---|
| Alert Name | Suspicious Privileged Role Assignment |
| Severity | High |
| Status | Investigated |
| Classification | Simulated True Positive |
| Data Source | Microsoft Entra ID Audit Logs |
| SIEM Platform | Microsoft Sentinel |
| Investigation Platform | Microsoft Defender XDR |
| Primary MITRE ATT&CK Technique | T1098.003 - Additional Cloud Roles |
| Environment | Simulated Lab |

## Incident Description

A standard user account received a privileged Microsoft Entra ID role outside the expected administrative process.

### Simulated affected account

```text
analyst-user@contoso-lab.com
```

### Simulated initiating account

```text
cloud-admin@contoso-lab.com
```

### Simulated assigned role

```text
Global Administrator
```

The initiating account had authenticated from an unfamiliar IP address shortly before modifying the role assignment.

> All identities, domains, roles, IP addresses, and events in this scenario are fictional.

## Investigation Objectives

The objectives of the investigation were to:

1. Confirm that the role assignment occurred.
2. Identify the actor responsible for the assignment.
3. Determine whether the activity was authorized.
4. Review sign-ins associated with the initiating account.
5. Review sign-ins associated with the affected account.
6. Identify other role assignments performed by the same actor.
7. Review changes to authentication methods.
8. Search for newly created users, applications, or service principals.
9. Determine whether privileged access was used.
10. Recommend containment, remediation, and escalation actions.

## Initial Evidence

The simulated alert contained the following indicators:

- A standard account received a highly privileged role.
- No approved change request was associated with the assignment.
- The assignment occurred outside the account’s normal administrative activity.
- The initiating account authenticated from an unfamiliar source IP.
- Additional directory audit activity followed the role assignment.
- The affected account had no previous administrative role history.

## Incident Timeline

| Time | Simulated Event |
|---|---|
| 14:02 | Administrative account authenticates from an unfamiliar IP |
| 14:05 | Administrative session accesses Microsoft Entra ID |
| 14:08 | Standard user receives a privileged directory role |
| 14:10 | Authentication method information is reviewed |
| 14:13 | A new application registration is attempted |
| 14:15 | Microsoft Sentinel generates an alert |
| 14:18 | SOC investigation begins |
| 14:23 | Unauthorized role assignment is confirmed |
| 14:25 | Containment and escalation are recommended |

## Investigation Process

### Step 1: Validate the Alert

The alert was reviewed to confirm:

- Alert timestamp.
- Initiating account.
- Target account.
- Assigned role.
- Assignment scope.
- Operation result.
- Source IP address.
- Related directory audit events.
- Related identity alerts.
- Previous role assignments involving the same accounts.

The role assignment was confirmed in the simulated audit data.

### Step 2: Review Privileged Role Assignments

Microsoft Entra ID audit logs were searched for role-management activity.

```kql
AuditLogs
| where Category =~ "RoleManagement"
| where OperationName has_any (
    "Add member to role",
    "Add eligible member to role",
    "Add member to directory role"
)
| extend
    InitiatingUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatingIP = tostring(InitiatedBy.user.ipAddress)
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatingUser,
    InitiatingIP,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated desc
```

### Step 3: Identify the Initiating Account

The initiating account was examined to determine:

- Normal administrative responsibilities.
- Previous role-management activity.
- Recent successful and failed sign-ins.
- Source locations and IP addresses.
- Authentication requirements.
- Conditional Access results.
- Device information.
- Related identity risk events.
- Recent password or MFA changes.

### Sign-in review for initiating account

```kql
let InitiatingAccount = "cloud-admin@contoso-lab.com";
SigninLogs
| where UserPrincipalName =~ InitiatingAccount
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ClientAppUsed,
    ResultType,
    ResultDescription,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    DeviceDetail,
    CorrelationId
| order by TimeGenerated desc
```

### Step 4: Review Failed and Successful Authentication

The investigation compared failed sign-ins with successful authentication activity.

```kql
let InitiatingAccount = "cloud-admin@contoso-lab.com";
SigninLogs
| where UserPrincipalName =~ InitiatingAccount
| summarize
    FailedSignIns = countif(ResultType != 0),
    SuccessfulSignIns = countif(ResultType == 0),
    SourceIPs = make_set(IPAddress, 20),
    Applications = make_set(AppDisplayName, 20),
    FirstObserved = min(TimeGenerated),
    LastObserved = max(TimeGenerated)
    by UserPrincipalName
```

### Step 5: Review the Target Account

The account receiving the privileged role was investigated for:

- Previous role assignments.
- Sign-ins after the role assignment.
- Administrative portal access.
- Directory modifications.
- Application or service-principal changes.
- User and group modifications.
- Credential or authentication-method changes.
- Mailbox or file-access activity.

```kql
let TargetAccount = "analyst-user@contoso-lab.com";
SigninLogs
| where UserPrincipalName =~ TargetAccount
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ResultType,
    ResultDescription,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    DeviceDetail
| order by TimeGenerated asc
```

### Step 6: Search for Role Use After Assignment

The investigation searched for directory changes performed by the newly privileged account.

```kql
let TargetAccount = "analyst-user@contoso-lab.com";
AuditLogs
| extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
| where InitiatingUser =~ TargetAccount
| project
    TimeGenerated,
    Category,
    OperationName,
    Result,
    ResultReason,
    InitiatingUser,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated asc
```

### Step 7: Search for Additional Role Assignments

The analyst searched for other accounts modified by the same initiating identity.

```kql
let InitiatingAccount = "cloud-admin@contoso-lab.com";
AuditLogs
| where Category =~ "RoleManagement"
| extend
    InitiatingUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatingIP = tostring(InitiatedBy.user.ipAddress)
| where InitiatingUser =~ InitiatingAccount
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatingUser,
    InitiatingIP,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated asc
```

### Step 8: Review Authentication-Method Changes

Unauthorized authentication-method changes could allow an attacker to maintain access after a password reset.

```kql
AuditLogs
| where OperationName has_any (
    "Register security information",
    "Update user",
    "User registered security info",
    "Admin registered security info",
    "Delete user authentication method",
    "Add authentication method"
)
| extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatingUser,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated desc
```

### Step 9: Review Application and Service-Principal Activity

The investigation searched for suspicious cloud application changes.

```kql
AuditLogs
| where Category has_any (
    "ApplicationManagement",
    "ServicePrincipal"
)
| where OperationName has_any (
    "Add application",
    "Add service principal",
    "Add service principal credentials",
    "Update application",
    "Consent to application"
)
| extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
| project
    TimeGenerated,
    Category,
    OperationName,
    Result,
    InitiatingUser,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated desc
```

### Step 10: Determine the Scope

The analyst should identify:

- Accounts receiving unauthorized roles.
- Roles and permissions assigned.
- Administrative actions performed.
- Applications or service principals created.
- Authentication methods added or modified.
- Groups or users changed.
- Files, mailboxes, or cloud resources accessed.
- Sessions associated with compromised identities.
- Other accounts authenticating from the suspicious IP.
- Whether the activity remained limited to one tenant or subscription.

### Search for accounts using the suspicious IP

```kql
let SuspiciousIP = "198.51.100.25";
SigninLogs
| where IPAddress == SuspiciousIP
| summarize
    Accounts = make_set(UserPrincipalName, 50),
    Applications = make_set(AppDisplayName, 50),
    SuccessfulSignIns = countif(ResultType == 0),
    FailedSignIns = countif(ResultType != 0),
    FirstObserved = min(TimeGenerated),
    LastObserved = max(TimeGenerated)
    by IPAddress
```

> The example IP address is reserved for documentation and simulation. Replace placeholders only with authorized lab or sanitized information.

## Findings

The simulated investigation identified:

- A privileged role assigned to a standard account.
- No documented business justification for the assignment.
- Authentication of the initiating account from an unfamiliar IP address.
- Successful sign-in shortly before the role modification.
- Directory activity performed by the newly privileged account.
- An attempted application registration after privilege elevation.
- No prior administrative history for the affected account.
- No evidence that the assignment was part of an approved access process.

The combined evidence supported unauthorized privilege escalation.

## Root Cause Analysis

The simulated root cause was:

**Compromise of an existing administrative account, followed by unauthorized assignment of a privileged Microsoft Entra ID role to a standard user account.**

The attacker used the compromised administrator’s valid session to modify cloud permissions and establish an additional privileged identity.

The activity was enabled by the following simulated control gaps:

- The administrative account was successfully accessed from an unfamiliar source.
- The privileged role assignment did not require additional approval.
- The assignment was not limited through just-in-time activation.
- The target account could receive standing administrative access.
- Alerting occurred after the role assignment was completed.

### Root cause chain

```text
Administrative account compromised
        ↓
Attacker obtains a valid cloud session
        ↓
Microsoft Entra ID administrative portal accessed
        ↓
Privileged role assigned to standard account
        ↓
Newly privileged account performs directory activity
        ↓
Persistence and expanded access become possible
        ↓
Microsoft Sentinel alert generated
```

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Relevance |
|---|---|---|---|
| Persistence | Account Manipulation: Additional Cloud Roles | T1098.003 | Additional administrative permissions assigned |
| Privilege Escalation | Account Manipulation: Additional Cloud Roles | T1098.003 | Standard account receives elevated cloud permissions |
| Defense Evasion | Valid Accounts | T1078 | Compromised legitimate account is used |
| Persistence | Additional Cloud Credentials | T1098.001 | Relevant if new credentials or authentication methods are added |
| Persistence | Create Account: Cloud Account | T1136.003 | Relevant if an additional cloud identity is created |

> Only techniques supported by actual evidence should be included in a real investigation.

## Potential Business Impact

Unauthorized cloud privilege escalation could result in:

- Access to sensitive organizational
