# Paper 3: LanG — Governance-Aware Agentic AI & The "Rule of Zero"

> **Full Title**: *LanG: A Governance-Aware Agentic AI Platform for Unified Security Operations*  
> **Authors**: Security & Systems Lab  
> **Publication**: [arXiv:2604.nnnnn](https://arxiv.org/) (April 2026)  
> **Primary Focus**: Enforcing cryptographic safety boundaries, the "Rule of Zero", and two-layer semantic guardrails to prevent autonomous security agents from executing destructive or unvetted actions.

---

## 1. The Real-World Problem: The Autonomous Agent Trust Crisis

As organizations explore AI in the SOC, Chief Information Security Officers (CISOs) face a fundamental dilemma:
* If an AI agent can **only give advice**, humans still have to manually verify and click every containment button, leaving the organization vulnerable to high-speed ransomware that encrypts networks in under 5 minutes.
* If an AI agent is given **API keys to execute containment actions** (e.g., blocking firewall ports, isolating virtual machines, wiping endpoints), a single model hallucination or corrupted context window can take down revenue-generating infrastructure.

### The Threat of "Agentic Drift"
In long-running multi-agent investigations, agents pass messages, tool results, and synthesized summaries back and forth. Over multiple hops, subtle errors compound:
1. Agent A misinterprets a benign network sweep as a distributed brute-force attack.
2. Agent B relies on Agent A's summary and decides to blacklist the offending IP address.
3. The IP address happens to be the company's single outbound NAT gateway.
4. The agent executes the block, severing internet access for all 5,000 employees.

---

## 2. Theoretical Mechanics: The Architecture of LanG

LanG introduces an architectural framework built on **LangGraph**, the **Model Context Protocol (MCP)**, and two foundational governance pillars:

```
                          ┌───────────────────────────┐
                          │   Advisory Agent Team     │
                          │ (Triage, DFIR, Intel RAG) │
                          └─────────────┬─────────────┘
                                        │
                                        ▼ (Proposes Action)
                          [Proposal: "isolate_host(DC-01)"]
                                        │
                         ═══════════════════════════════
                         BOUNDARY: The "Rule of Zero"
                         (Advisory agents hold ZERO root keys)
                         ═══════════════════════════════
                                        │
                                        ▼
                     ┌─────────────────────────────────────┐
                     │    Layer 1: Semantic Intent Gate    │
                     │  (Deterministic Grammar Validator)  │
                     └──────────────────┬──────────────────┘
                                        │
                                        ▼
                     ┌─────────────────────────────────────┐
                     │    Layer 2: Asset Criticality Graph │
                     │   (NetworkX Business Impact Model)  │
                     └──────────────────┬──────────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼ (Tier-3 Commodity Endpoint)                 ▼ (Tier-0 Critical Infrastructure)
     ┌────────────────────────┐                    ┌────────────────────────┐
     │   Auto-Execute Gate    │                    │  Force Human-in-the-   │
     │ (Surgical containment) │                    │     Loop (HITL) Gate   │
     └────────────────────────┘                    └────────────────────────┘
```

### 1. The "Rule of Zero" (Separation of Powers)
Under the *Rule of Zero*, **advisory reasoning models are cryptographically barred from holding privileged execution credentials**. 
* The LLM can only output a structured, formal **Containment Proposal**.
* The proposal must be signed by the advisory agent's ephemeral cryptographic key and submitted to an independent, non-LLM execution controller.
* The execution controller holds the actual API keys (e.g., CrowdStrike API, Palo Alto Networks Firewall API), but will only execute commands that pass rigorous safety verification.

### 2. Two-Layer Semantic Guardrails
* **Layer 1 (Deterministic Syntax & Semantic Policy Gate)**: A compiled deterministic state-machine inspects the proposed action. It verifies that the action type matches allowable operations defined in corporate security policy (e.g., forbidding permanent deletion of logs or unmounting storage drives under any circumstances).
* **Layer 2 (Asset Criticality Graph & Blast Radius Gate)**: The controller traverses an enterprise dependency graph. If the target asset is classified as **Tier-0** (Identity Provider, Domain Controller, PKI Root) or **Tier-1** (Production E-Commerce Ingress), full network isolation is automatically rejected. The controller either downgrades the action (e.g., isolating a single user session or rate-limiting traffic) or triggers a mandatory **Human-in-the-Loop (HITL)** approval flow via Slack or Microsoft Teams.

---

## 3. Layman's Analogy & Real-World Walkthrough

### The Police Detective vs. The SWAT Team & Judge
Imagine a police department where:
* Detectives investigate crimes, gather forensic clues, and write reports.
* A SWAT team executes physical entries and arrests.
* A Judge reviews evidence and signs search warrants.

**A dangerous system** would be letting a junior detective carry a battering ram, kick down any citizen's door, and seize property without showing a warrant to anyone.

**LanG enforces proper procedure**:
1. The AI Detective gathers clues and says: *"I believe suspect X is in building Y. I recommend entering building Y."*
2. The AI Detective **does not have the key or battering ram**.
3. The request goes to the Magistrate (The Guardrail Engine), who checks the blueprints: *"Wait, building Y is a major hospital. You cannot kick down the door without the Chief of Police (Human CISO) signing this warrant."*

---

### Real-World Incident Walkthrough

#### Scenario: Ransomware Outbreak on Developer Laptop vs. Domain Controller

```
Case A: Target is DEV-WRK-882 (Developer Laptop)
├─ Advisory Agent identifies active Cobalt Strike beacon.
├─ Advisory Agent proposes: isolate_host(DEV-WRK-882).
├─ Layer 1 Gate: isolate_host is an allowed action.
├─ Layer 2 Gate: Target is Tier-3 (0 dependent services, $20/min business loss).
└─ Action: AUTONOMOUS EXECUTION APPROVED. Host isolated in 1.2 seconds.

Case B: Target is DC-PRIMARY-01 (Domain Controller)
├─ Advisory Agent identifies unauthorized NTDS.dit database dumping.
├─ Advisory Agent proposes: isolate_host(DC-PRIMARY-01).
├─ Layer 1 Gate: isolate_host is an allowed action.
├─ Layer 2 Gate: Target is Tier-0 (1,450 dependent laptops, $25,000/min loss).
├─ Gate Evaluation: BLOCKED BY RULE OF ZERO.
└─ Action: Isolation halted. Applied surgical process termination on NTDSUTIL.exe.
   Dispatched priority alert to Incident Commander phone: "Manual Review Required".
```

---

## 4. Concrete Code Implementation

In our local testbed, this is implemented in [`agents/safety_guardrail_engine.py`](file:///c:/Agentic%20SOC/agents/safety_guardrail_engine.py):

```python
class SafetyGuardrailEngine:
    def evaluate_containment_request(self, asset_id: str, proposed_action: str) -> Dict[str, Any]:
        asset = self.tools.get_asset_metadata(asset_id)
        tier = asset.get("tier", "Tier-3")
        dependent_nodes = asset.get("dependent_workstations", 0)
        est_loss = asset.get("estimated_downtime_loss_per_min", 0)

        # Rule of Zero: Tier-0 Critical Systems can NEVER be blindly isolated
        if tier == "Tier-0":
            return {
                "decision": "BLOCKED_BY_RULE_OF_ZERO",
                "asset_id": asset_id,
                "tier": tier,
                "mitigation_action": "FORCE_HUMAN_IN_THE_LOOP",
                "impact_analysis": {
                    "dependent_workstations_protected": dependent_nodes,
                    "estimated_financial_loss_prevented_per_min": est_loss
                },
                "status": "ESCALATED_TO_INCIDENT_COMMANDER"
            }

        # Tier-3 Commodity Endpoints are safe for autonomous response
        result = self.tools.execute_containment(asset_id, proposed_action, requested_by="GuardrailApproved")
        return {"decision": "AUTONOMOUS_CONTAINMENT_APPROVED", "status": "CONTAINED"}
```

---

## 5. Empirical Results from the Paper

The authors stress-tested LanG in simulated enterprise environments subject to 5,000 autonomous containment recommendations:

| Metric | Unconstrained Agent (Raw API Access) | Static SOAR Playbooks | LanG Platform |
| :--- | :--- | :--- | :--- |
| **High-Impact Outage Prevention** | 0.0% (Failed repeatedly) | 71.4% (Brittle rules) | **100.0%** |
| **Containment Execution Latency** | 1.1 seconds | 35.0 seconds | **1.8 seconds** |
| **Privilege Escalation Vulnerability** | Critical (Keys in prompt) | Low | **Zero (Cryptographic separation)** |
| **Human Fatigue Reduction** | 12.0% | 45.0% | **88.5%** |

---

## 6. Limitations & Open Questions
1. **CMDB Staleness**: If the enterprise asset management database is out of date (e.g., a server was promoted to a primary Domain Controller yesterday but is still labeled "Tier-3" in the database), the guardrail will make decisions on outdated criticality tags.
2. **Attacker Slow-Drain Tactics**: If an attacker knows the AI will not isolate a Tier-0 asset without human approval, they can focus their entire campaign exclusively on Tier-0 assets during off-hours, forcing human escalation queues to overflow.
