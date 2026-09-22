# Eros | Prompt Injection Incident Investigation

## Executive Summary

This case study documents a hands-on incident response investigation completed in **Blue Team Labs Online (BTLO)** involving the abuse of an AI assistant embedded in the Eros web application.

The investigation required correlating **Nginx access logs, AI interaction logs, user activity, source IP addresses, application behavior, and Python/Flask source code** to reconstruct suspicious activity.

The investigation confirmed **Prompt Injection** as the initial access mechanism. Suspicious activity was associated with the account `noone`, user ID `4273`, and source IP `158.173.24.3`.

Analysis of the AI interaction logs revealed a progression from seemingly normal questions to requests involving the assistant's system prompt, internal security information, administrative credentials, passwords, and administrative URLs.

Rather than relying only on the challenge questions, I investigated the underlying telemetry and application code to understand how the AI assistant was being abused.

---

## Incident Overview

| Category | Finding |
|---|---|
| Platform | Blue Team Labs Online |
| Scenario | Eros |
| Category | Incident Response |
| Initial Access | **Prompt Injection** |
| Suspicious Account | `noone` |
| User ID | `4273` |
| Suspicious Source IP | `158.173.24.3` |
| Targeted Endpoint | `/api/ai-assistant` |
| Application Component | `/opt/eros-io/app/routes/ai.py` |
| Function Investigated | `ai_assistant()` |
| Primary Data Sources | Nginx logs, AI interaction logs, application source code |

---

## Investigation Objectives

The investigation focused on answering several core incident response questions:

- What initial access mechanism was used?
- Which account was associated with the suspicious activity?
- Which source IP was responsible?
- How was the AI assistant used during the incident?
- What information was the attacker attempting to obtain?
- Which application component handled the suspicious requests?
- What did the surrounding web activity reveal about the attack progression?

---

# Investigation

## 1. Initial Access Identification

Analysis of the available evidence ultimately identified **Prompt Injection** as the initial access mechanism.

This conclusion was validated by the BTLO investigation platform.

evidence/01-prompt-injection-confirmed.png

The confirmation was important because the investigation initially considered multiple possible attack mechanisms. I avoided treating an unverified hypothesis as fact until the evidence supported the final classification.

---

## 2. HTTP Activity Analysis

I analyzed the Nginx access logs and identified repeated HTTP requests associated with the suspicious source IP:

```text
158.173.24.3
```

The IP repeatedly interacted with:

```text
POST /api/ai-assistant
```

The requests appeared while navigating multiple areas of the application, including profile, discovery, and administrative locations.

evidence/02-ai-assistant-http-activity.png

This provided the web-server side of the investigation and established that the suspicious source repeatedly interacted with the AI functionality.

---

## 3. AI Interaction Log Analysis

The next step was analyzing the dedicated AI interaction logs.

This provided significantly richer context than the HTTP access logs because the records contained information such as:

```text
user_id
username
source IP
user message
AI response
timestamp
```

The activity correlated:

```text
Username: noone
User ID:   4273
IP:        158.173.24.3
```

with a series of increasingly suspicious AI interactions.

evidence/03-attacker-ai-interaction-timeline.png

---

## 4. Prompt Injection / Reconnaissance Activity

The AI interaction logs revealed a progression in the questions submitted to the assistant.

Examples of the observed requests included questions concerning:

```text
How the assistant works
System prompt information
Internal security details
Administrative credentials
Administrative passwords
Administrative URLs
```

The progression was significant.

Instead of treating each prompt as an isolated request, I correlated the messages chronologically to understand the attacker's apparent investigative behavior against the AI-enabled application.

evidence/04-prompt-injection-reconnaissance.png

This correlation helped connect the confirmed prompt-injection technique with the observable application activity.

---

# Source Code Investigation

## 5. Locating the AI Assistant Endpoint

Log analysis identified `/api/ai-assistant` as a central component of the suspicious activity.

I therefore moved from log analysis into application source-code review to understand how the endpoint processed requests.

The relevant application code was located under:

```text
/opt/eros-io/app/routes/ai.py
```

The source contained the AI assistant route:

```python
@ai_bp.route('/ai-assistant', methods=['POST'])
@login_required
def ai_assistant():
```

evidence/05-ai-assistant-source-code-review.png

This helped connect the network-level evidence to the application component responsible for processing the requests.

---

## 6. Request Handling Analysis

I continued reviewing the `ai_assistant()` implementation to understand what information was accepted and recorded during an AI interaction.

The function handled values including:

```python
user_message = data.get('message', '')
history = data.get('history', [])
user_id = current_user.id
username = current_user.username
ip = request.remote_addr
```

The application also logged incoming messages together with identity and source information.

evidence/06-ai-assistant-request-handling.png

This logging proved particularly useful during the investigation because it allowed activity from the web logs to be correlated with:

```text
Account
User ID
Source IP
Prompt content
AI response
Timestamp
```

---

## 7. Relevant Application Code Path

The investigation focused heavily on the AI assistant processing path:

```text
/opt/eros-io/app/routes/ai.py
```

and the function:

```text
ai_assistant()
```

evidence/07-vulnerable-ai-function-identified.png

> **Evidence note:** My public case study distinguishes between findings directly confirmed by the lab and code paths discovered during investigation. I avoid presenting an answer as challenge-confirmed unless the available evidence explicitly validates it.

This distinction is intentional and reflects the same evidence-based approach I would use when documenting a real security incident.

---

# Attack Timeline

The correlated evidence produced the following investigative sequence:

```text
Account activity involving "noone"
              |
              v
AI Assistant interaction
              |
              v
Questions about assistant behavior
              |
              v
Requests concerning system prompt
              |
              v
Requests for internal security information
              |
              v
Requests involving administrative information
              |
              v
Repeated /api/ai-assistant activity
              |
              v
Nginx + AI log correlation
              |
              v
Application source-code investigation
              |
              v
Prompt Injection confirmed
```

The investigation demonstrates why individual events should not be analyzed in isolation.

The strongest conclusions came from **correlating multiple evidence sources**.

---

# Key Findings

### Confirmed Initial Access

```text
Prompt Injection
```

### Suspicious Account

```text
noone
```

### Associated User ID

```text
4273
```

### Suspicious Source IP

```text
158.173.24.3
```

### Targeted Application Endpoint

```text
POST /api/ai-assistant
```

### Application Component Investigated

```text
/opt/eros-io/app/routes/ai.py
```

### Relevant Function

```text
ai_assistant()
```

### Attacker-Relevant AI Requests

The AI interaction logs contained requests concerning:

- Assistant behavior
- System prompt information
- Internal security details
- Administrative credentials
- Administrative password information
- Administrative URLs

---

# Evidence Correlation

One of the most valuable aspects of this investigation was correlating different telemetry sources instead of depending on a single IOC.

```text
Nginx Access Logs
        +
AI Interaction Logs
        +
Account Information
        +
Source IP
        +
HTTP Activity
        +
Application Source Code
        |
        v
Reconstructed Incident Activity
```

The Nginx logs established **where and when HTTP activity occurred**.

The AI interaction logs provided **who submitted the prompts and what was being requested**.

The application source code provided additional context about **how the targeted AI endpoint handled requests and recorded forensic information**.

Together, these sources produced a much stronger investigative picture.

---

# Security Recommendations

Based on the behavior investigated in this scenario, defensive measures for AI-enabled applications should include:

### 1. Treat AI Input as Untrusted

User-controlled prompts should be treated as untrusted input.

Security-sensitive application behavior should not depend solely on the model following natural-language instructions.

### 2. Protect Sensitive Context

Credentials, secrets, internal configuration data, administrative URLs, and other sensitive information should not be unnecessarily exposed to model-accessible context.

### 3. Enforce Authorization Outside the Model

Access-control decisions should be enforced by deterministic application logic rather than relying on the AI assistant to decide whether information should be disclosed.

### 4. Monitor Suspicious AI Interactions

Security monitoring should consider patterns such as repeated attempts to obtain:

```text
System prompts
Credentials
Secrets
Configuration information
Administrative resources
Internal security information
```

### 5. Preserve AI Audit Telemetry

AI-enabled applications should maintain useful security telemetry where appropriate, including:

```text
Timestamp
User/account identifier
Source address
Endpoint
Prompt/request
Response outcome
```

Traditional web telemetry and AI-specific telemetry can complement each other during incident response.

---

# Skills Demonstrated

This investigation provided hands-on practice with:

- SOC / Incident Response Investigation
- Linux Log Analysis
- Nginx Access Log Analysis
- AI Security Investigation
- Prompt Injection Analysis
- Web Application Security
- IOC and Entity Correlation
- Account Activity Analysis
- Attack Timeline Reconstruction
- Python / Flask Source Code Review
- HTTP Request Analysis
- Evidence Validation
- Incident Documentation
- Evidence-Based Decision Making

---

# Analyst Takeaway

The most important lesson from this investigation was that an AI-related security incident should not be investigated solely as a conversation with a chatbot.

The suspicious prompts were only one source of evidence.

By combining:

```text
AI telemetry
+
Web server logs
+
Account context
+
Source IP activity
+
Application source code
```

I was able to reconstruct a much clearer representation of the suspicious activity.

This case also reinforced an important principle I apply throughout my security investigations:

> **Do not force the evidence to fit a hypothesis. Build the conclusion from evidence that can actually be validated.**

---

# Evidence

The public evidence directory contains only screenshots that contribute directly to the investigation narrative.

```text
evidence/
├── 01-prompt-injection-confirmed.png
├── 02-ai-assistant-http-activity.png
├── 03-attacker-ai-interaction-timeline.png
├── 04-prompt-injection-reconnaissance.png
├── 05-ai-assistant-source-code-review.png
├── 06-ai-assistant-request-handling.png
├── 07-vulnerable-ai-function-identified.png
└── 08-eros-investigation-completed.png
```

---

# Investigation Completion

The Eros incident response scenario was successfully completed on Blue Team Labs Online.

evidence/08-eros-investigation-completed.png

---

## Why This Case Matters

This investigation expanded my blue-team experience beyond traditional endpoint and malware alerts.

It required investigating a security incident involving an **AI-enabled web application**, while still applying core incident response practices:

```text
Identify
   ↓
Collect
   ↓
Correlate
   ↓
Investigate
   ↓
Validate
   ↓
Document
```

The scenario provided practical experience applying traditional SOC investigation methodology to an emerging attack surface: **AI-integrated applications**.

---

## Disclaimer

This investigation was performed in a **controlled cybersecurity training environment** provided through Blue Team Labs Online.

This case study is intended exclusively to document my hands-on cybersecurity learning, investigative methodology, technical analysis, and incident response skills.

Screenshots are selectively included to demonstrate investigative reasoning rather than reproduce the complete challenge or provide a step-by-step answer guide.
