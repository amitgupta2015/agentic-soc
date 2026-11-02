# Paper 1: AgentSOC — Narrative Counterfactual Reasoning & Structural Simulation

> **Full Title**: *AgentSOC: A Multi-Layer Agentic AI Framework for Security Operations Automation*  
> **Authors**: Joyjit Roy, et al.  
> **Publication**: IEEE International Conference on AI in Cybersecurity (IEEE ICAIC) / [arXiv:2604.20134](https://arxiv.org/abs/2604.20134) (April 2026)  
> **Primary Focus**: Eliminating confirmation bias in automated alert triage and preventing operational outages during autonomous remediation.

---

## 1. The Real-World Problem: The "Boy Who Cried Wolf" Dilemma

Modern Security Operations Centers (SOCs) are drowning in alerts. An enterprise with 10,000 employees typically generates **15,000 to 40,000 security alerts per day**. Over 90% of these alerts are triggered by routine administrative tasks:
* System administrators deploying monthly operating system patches.
* Database engineers running batch maintenance scripts.
* Backup software creating compressed archives across multiple network shares.

### Why Traditional Systems & Naive LLMs Fail
When an alert triggers (such as `Suspicious Encoded PowerShell Execution - MITRE ATT&CK T1059.001`), standard AI agents (using standard ReAct loops: *Thought $\to$ Action $\to$ Observation*) suffer from **confirmation bias**:
1. The AI reads the alert label: *"High Severity: Encoded PowerShell detected."*
2. The AI reasons: *"Encoded PowerShell is commonly used by Cobalt Strike and ransomware to hide commands."*
3. The AI concludes: *"This host is compromised! Execute immediate network isolation!"*

This causes two catastrophic failure modes:
* **Analyst Exhaustion**: Human analysts spend hours investigating false alarms, causing fatigue that allows real attacks to slip through undetected.
* **Self-Inflicted Outages**: An autonomous agent isolates a server running a benign backup script, accidentally disconnecting hundreds of employees or shutting down a revenue-generating production service.

---

## 2. Theoretical Mechanics: How AgentSOC Solves This

AgentSOC introduces a multi-layered cognitive architecture powered by two novel mathematical engines:

```
                          ┌───────────────────────────┐
                          │   Incoming Security Alert  │
                          │   (e.g., Encoded Command) │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                     ┌─────────────────────────────────────┐
                     │    Narrative Counterfactual Engine  │
                     └──────────────────┬──────────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼                                             ▼
     ┌───────────────────────┐                     ┌───────────────────────┐
     │ Hypothesis A (Attack) │                     │ Hypothesis B (Benign) │
     │ "Attacker persistence"│                     │ "Scheduled IT patch"  │
     └───────────┬───────────┘                     └───────────┬───────────┘
                 │                                             │
                 │          [Active Falsification Queries]     │
                 │   • Look for IT Change Ticket               │
                 │   • Verify Digital Signature                │
                 │   • Check Parent Daemon Authenticity        │
                 │                                             │
                 └──────────────────────┬──────────────────────┘
                                        │
                                        ▼
                     ┌─────────────────────────────────────┐
                     │       Evidence Balance Verdict      │
                     │  (e.g., Benign Confirmed: 95% Conf) │
                     └──────────────────┬──────────────────┘
                                        │ (If Malicious)
                                        ▼
                     ┌─────────────────────────────────────┐
                     │     Structural Simulation Engine    │
                     │ (Asset Graph & Blast-Radius Model)  │
                     └──────────────────┬──────────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼ (Tier-3 Dev Machine)                        ▼ (Tier-0 Domain Controller)
     ┌────────────────────────┐                    ┌────────────────────────┐
     │  Autonomous Isolation  │                    │ Intercept & Force HITL │
     │ (Zero Business Impact) │                    │ (Prevent Enterprise KD)│
     └────────────────────────┘                    └────────────────────────┘
```

### 1. Narrative Counterfactual Engine
Instead of seeking evidence to *confirm* the alert, the agent is mathematically required to formulate **competing counter-hypotheses**:
$$\mathcal{H}_{malicious} \quad \text{vs.} \quad \mathcal{H}_{benign}$$

The agent then systematically generates **falsification queries** aimed at disproving the threat:
* *"If this were an innocent admin, what surrounding artifacts MUST exist?"*
  1. An approved change ticket in ServiceNow or Jira with a matching timestamp and machine ID.
  2. A verified cryptographic signature on the binary from a trusted vendor (e.g., Microsoft, CrowdStrike).
  3. A legitimate parent process tree (e.g., `CcmExec.exe` for Microsoft SCCM rather than `WINWORD.EXE`).

If the falsification evidence is verified, $\mathcal{H}_{benign}$ wins, and the alert is automatically closed with an audit explanation. If falsification fails (no ticket, unsigned binary, non-standard parent), $\mathcal{H}_{malicious}$ is confirmed with high confidence.

### 2. Structural Simulation Engine
Before an autonomous remediation command (like `isolate_host` or `revoke_credentials`) is dispatched, the action is passed to a simulation layer that models the enterprise as a **directed dependency graph** $G = (V, E)$:
* **Nodes ($V$)**: Enterprise assets tagged by criticality tier (`Tier-0`: Domain Controllers/PKI, `Tier-1`: Payment gateways, `Tier-3`: Laptops).
* **Edges ($E$)**: Dependent services (e.g., 1,450 workstations dependent on `DC-01` for Kerberos authentication).

The simulator computes the **Operational Blast Radius** $\mathcal{B}$:
$$\mathcal{B}(\text{action}, v) = \sum_{u \in \text{Descendants}(v)} \text{LossPerMinute}(u) \times \Delta t$$

If $\mathcal{B}$ exceeds the allowable automated risk threshold, the isolation command is intercepted, downgraded to surgical traffic shaping, and routed to an Incident Commander with an impact brief.

---

## 3. Layman's Analogy & Step-by-Step Incident Walkthrough

### The ER Doctor Metaphor
Imagine a patient walks into the Emergency Room with chest tightness.
* **The Naive Doctor (Standard AI)**: *"Chest pain! Heart attack! Wheel them into emergency open-heart surgery right now!"* The patient actually just had acid reflux from spicy food; undergoing unneeded major surgery causes massive harm.
* **The AgentSOC Doctor**: *"Chest pain could be a heart attack ($H_A$), but it could also be acid reflux or anxiety ($H_B$). Before cutting them open, let's run an EKG and check their medical history."* The EKG is normal, the patient ate chili an hour ago, and the doctor safely prescribes an antacid.

---

### Step-by-Step Real Incident Scenario

#### Scenario: The Ambiguous 3:00 AM Command
A detection rule fires in Microsoft Defender:
```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AQwBsAGEAcwBzACAAVwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwA=
```

#### How the Two Agents Handle It:

| Step | Standard Baseline ReAct Agent | AgentSOC Architecture |
| :--- | :--- | :--- |
| **Step 1: Observation** | Reads `ExecutionPolicy Bypass` and base64 encoded string. | Reads alert, but notes parent process is `CcmExec.exe`. |
| **Step 2: Hypothesis** | *"This matches malware obfuscation. Compromise confirmed."* | Formulates $H_A$: Attacker script vs. $H_B$: SCCM Patch Deployment. |
| **Step 3: Investigation** | Queries VirusTotal for generic `powershell.exe` hash (inconclusive). | Decodes command: `Invoke-WmiMethod -Class Win32_Process ... KB504821.exe`. Queries ITSM ticket system for `KB504821`. |
| **Step 4: Discovery** | No further context collected. | Finds approved ticket: `CHG-99214-PATCH-TUESDAY` signed by Change Advisory Board. Validates Microsoft digital certificate. |
| **Step 5: Action** | **Isolates host immediately**, disconnecting an engineer during a deployment. | **Closes alert as Verified Benign Admin Activity**, logging the verified ticket ID. |

---

## 4. Concrete Code Implementation

In our local testbed, this is implemented in [`agents/counterfactual_agent.py`](file:///c:/Agentic%20SOC/agents/counterfactual_agent.py):

```python
class CounterfactualAgent:
    def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        context = alert.get("context", {})
        falsification_evidence = []
        
        # 1. Proactively query negative/falsifying evidence
        ticket_id = context.get("change_ticket_id")
        if ticket_id:
            ticket = self.tools.lookup_change_ticket(ticket_id)
            if ticket.get("found"):
                falsification_evidence.append(f"Approved Ticket: {ticket_id}")

        if "Verified" in context.get("digital_signature", ""):
            falsification_evidence.append("Cryptographic signature valid from trusted vendor.")

        if context.get("parent_is_trusted_service"):
            falsification_evidence.append("Parent process is verified enterprise daemon.")

        # 2. Demand counterfactual evaluation from LLM
        prompt = f"""
ALERT UNDER ANALYSIS: {alert.get('alert_id')}
Command: {alert.get('decoded_command') or alert.get('command_line')}
FALSIFICATION EVIDENCE: {json.dumps(falsification_evidence)}

Task: Balance Hypothesis A (Attacker Action) vs Hypothesis B (Legitimate Admin).
Require conclusive falsification proof to confirm Benign.
"""
        return self.llm.query(prompt, system_prompt="You are a counterfactual falsification engine.")
```

---

## 5. Empirical Results from the Paper

The authors evaluated AgentSOC against 12,400 enterprise alerts collected across hybrid cloud environments:

| Metric | Traditional Rule Baseline | Standard ReAct LLM Agent | AgentSOC |
| :--- | :--- | :--- | :--- |
| **False Positive Rate (FPR)** | 88.4% | 42.1% | **2.3%** |
| **False Negative Rate (FNR)** | 4.8% | 3.1% | **0.8%** |
| **Unintended Outage Rate** | 12.0% | 18.5% | **0.0%** (100% prevented) |
| **Mean Time to Triage (MTTT)** | 45 minutes | 4.2 minutes | **1.1 minutes** |

---

## 6. Limitations & Open Questions
1. **Compromised Service Accounts**: If an advanced attacker compromises both the endpoint *and* an approved change ticket ID in ServiceNow, the counterfactual reasoner could be misled into marking an attack as an approved patch.
2. **Context Latency**: Querying multiple IT databases (CMDB, Jira, PKI certificate logs) adds network latency (1–3 seconds per alert).
