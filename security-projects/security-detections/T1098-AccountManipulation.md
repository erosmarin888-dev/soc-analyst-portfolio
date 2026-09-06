# T1098 - Account Manipulation Detection

## Overview

This detection identifies potentially unauthorized changes to Microsoft Entra ID accounts, authentication methods, group memberships, and directory roles.

An attacker who has compromised an identity may modify the account or assign additional permissions to establish persistence, retain access, or escalate privileges.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique | Account Manipulation |
| Technique ID | T1098 |
| Tactics | Persistence, Privilege Escalation |
| Data Source | Microsoft Entra ID Audit Logs |
| Detection Platform | Microsoft Sentinel |
| Primary Table | `AuditLogs` |

### Related sub-techniques

| Technique ID | Name |
|---|---|
| T1098.001 | Additional Cloud Credentials |
| T1098.003 | Additional Cloud Roles |
| T1098.005 | Device Registration |
| T1098.007 | Additional Local or Domain Groups |

---

## Objective

Detect security-sensitive identity changes that may allow an attacker to:

- Add credentials to a compromised identity
- Register or modify authentication methods
- Add an account to a privileged group
- Assign a Microsoft Entra directory role
- Change account properties
- Establish identity-based persistence
- Increase the permissions of an existing account

---

## Data Requirements

The following telemetry is required:

- Microsoft Entra ID audit logs
- `AuditLogs` table available in Microsoft Sentinel
- Audit log ingestion through Microsoft Entra diagnostic settings
- Sufficient log retention for investigation and correlation

Optional supporting telemetry:

- `SigninLogs`
- `AADUserRiskEvents`
- `IdentityInfo`
- Microsoft Defender XDR alerts
- Microsoft Entra ID Protection risk information

---

## Detection Logic

The detection searches Microsoft Entra audit events for operations associated with security-sensitive account manipulation.

Monitored operations include:

- Adding a member to a group
- Adding a member to a directory role
- Updating a user
- Resetting or changing a password
- Registering security information
- Adding or updating authentication methods
- Adding credentials to an application or service principal

An individual event is not automatically malicious. The analyst must determine whether the initiating identity, target identity, operation, and business context are expected.

---

## Microsoft Sentinel KQL Query

```kql
let SensitiveOperations = dynamic([
    "Add member to group",
    "Add member to role",
    "Add eligible member to role",
    "Add scoped member to role",
    "Update user",
    "Reset password",
    "Change password (self-service)",
    "Register security info",
    "User registered security info",
    "Admin registered security info",
    "Update user authentication method",
    "Delete user authentication method",
    "Add service principal credentials",
    "Update application - Certificates and secrets management",
    "Update service principal"
]);
AuditLogs
| where TimeGenerated >= ago(24h)
| where Result =~ "success"
| where OperationName in~ (SensitiveOperations)
| extend InitiatingUser =
    tostring(InitiatedBy.user.userPrincipalName),
    InitiatingUserId =
    tostring(InitiatedBy.user.id),
    InitiatingApplication =
    tostring(InitiatedBy.app.displayName),
    InitiatingIPAddress =
    tostring(InitiatedBy.user.ipAddress)
| mv-expand TargetResource = TargetResources
| extend TargetDisplayName =
    tostring(TargetResource.displayName),
    TargetUserPrincipalName =
    tostring(TargetResource.userPrincipalName),
    TargetResourceType =
    tostring(TargetResource.type),
    ModifiedProperties =
    TargetResource.modifiedProperties
| project
    TimeGenerated,
    OperationName,
    Category,
    Result,
    ResultReason,
    InitiatingUser,
    InitiatingUserId,
    InitiatingApplication,
    InitiatingIPAddress,
    TargetDisplayName,
    TargetUserPrincipalName,
    TargetResourceType,
    ModifiedProperties,
    CorrelationId
| order by TimeGenerated desc
```

---

## Focused Detection: Privileged Role Assignment

This query focuses on successful Microsoft Entra role-assignment operations.

```kql
AuditLogs
| where TimeGenerated >= ago(24h)
| where Result =~ "success"
| where Category =~ "RoleManagement"
| where OperationName has_any (
    "Add member to role",
    "Add eligible member to role",
    "Add scoped member to role"
)
| extend InitiatingUser =
    tostring(InitiatedBy.user.userPrincipalName),
    InitiatingApplication =
    tostring(InitiatedBy.app.displayName),
    InitiatingIPAddress =
    tostring(InitiatedBy.user.ipAddress)
| mv-expand TargetResource = TargetResources
| extend TargetDisplayName =
    tostring(TargetResource.displayName),
    TargetUserPrincipalName =
    tostring(TargetResource.userPrincipalName),
    TargetResourceType =
    tostring(TargetResource.type),
    ModifiedProperties =
    TargetResource.modifiedProperties
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatingUser,
    InitiatingApplication,
    InitiatingIPAddress,
    TargetDisplayName,
    TargetUserPrincipalName,
    TargetResourceType,
    ModifiedProperties,
    CorrelationId
| order by TimeGenerated desc
```

---

## Focused Detection: Authentication Method Changes

This query searches for successful security-information and authentication-method changes.

```kql
AuditLogs
| where TimeGenerated >= ago(24h)
| where Result =~ "success"
| where OperationName has_any (
    "Register security info",
