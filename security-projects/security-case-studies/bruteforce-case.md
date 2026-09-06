# Brute Force Investigation

## Scenario

A Microsoft Sentinel alert was triggered after detecting multiple failed logon attempts against a user account.

## Alert Information

| Field | Value |
|---------|---------|
| Alert Type | Brute Force Detection |
| Severity | Medium |
| MITRE ATT&CK | T1110 |
| Status | Investigated |

## Initial Findings

The account generated more than 10 failed authentication attempts within a short time period.

Observed indicators:

- Multiple failed logon attempts
- Authentication failures from a single source
- Repeated access attempts against the same account

## Investigation Process

### Step 1 - Review Alert

Validated the alert details and identified the targeted account.

### Step 2 - Review Authentication Activity

Analyzed authentication activity to determine:

- Number of failures
- Source location
- Timeline of events

### Step 3 - Determine Scope

Reviewed whether other accounts were targeted from the same source.

### Step 4 - Assess Risk

No successful authentication attempts were observed.

Risk level remained Medium.

## Detection Logic

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedAttempts=count() by AccountName
| where FailedAttempts > 10
