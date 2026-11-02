# Paper 5: The Grand Survey — LLMs in the SOC & The 6 Levels of Autonomy

> **Full Title**: *Large Language Models for Security Operations Centers: A Comprehensive Survey*  
> **Authors**: Ali Habibzadeh, Farid Feyzi, Reza Ebrahimi Atani  
> **Publication**: [arXiv:2509.10858](https://arxiv.org/abs/2509.10858) (Updated late 2025)  
> **Companion Framework**: *The SOC Autonomy Standard (Levels 0–5)* (SIRP Labs & ACM Digital Library)  
> **Primary Focus**: A systemic meta-analysis of over 180 research implementations mapping generative AI and agentic systems across the 4 phases of security operations, establishing a formal capability-maturity taxonomy.

---

## 1. The Big Picture: Why We Need an Autonomy Classification

Every cybersecurity vendor today claims to offer an "Autonomous AI SOC". However, marketing language blurs the lines between:
* A basic chatbot that merely summarizes a ticket.
* A playbook that runs a linear script.
* A true multi-agent system that autonomously formulates hypotheses, pivots across enterprise telemetry, and executes risk-governed response actions.

To bring scientific rigor to this domain, researchers synthesized insights from over 180 academic and enterprise papers, establishing the **SOC Autonomy Classification (Levels 0 to 5)**—modeled after the automotive industry's SAE standards for self-driving vehicles.

---

## 2. The 6 Levels of SOC Autonomy

```
Level 0: Manual Operations      ──► Traditional SIEM (Human does 100% of the cognitive work)
Level 1: Assisted Automation    ──► Legacy SOAR (Runs pre-built, static IF-THEN playbooks)
Level 2: Augmented Triage       ──► AI Co-Pilots (Summarizes logs, human executes all queries)
Level 3: Conditional Autonomy   ──► Modern Agentic SOC (Multi-agent team handles L1/L2, human oversees)
Level 4: High Autonomy          ──► Self-Directing SOC (Full investigation & containment; human audits)
Level 5: Full Autonomy          ──► Theoretical Horizon (Self-defending network, discovers 0-days)
```

### Detailed Breakdown of the Levels:

| Level | Designation | System Role | Human Role | Typical Technology |
| :---: | :--- | :--- | :--- | :--- |
| **L0** | **Manual Operations** | Ingests logs and displays alerts based on static signatures. | 100% of triage, correlation, query writing, and remediation. | Traditional SIEMs (QRadar, ArcSight, basic Elastic). |
| **L1** | **Assisted Automation** | Executes rigid, pre-scripted DAG playbooks when an exact alert ID triggers. | Builds and maintains playbooks; handles every edge case and exception. | First-Gen SOAR (Cortex XSOAR, Splunk Phantom). |
| **L2** | **Augmented Triage** | Generates natural language summaries of alerts and suggests query drafts. | Reviews summaries, validates suggestions, writes queries, makes all decisions. | Security Co-Pilots (Microsoft Security Copilot). |
| **L3** | **Conditional Autonomy** *(State of the Art)* | Multi-agent team autonomously triages, hunts for context, correlates telemetry, and isolates low-risk commodity threats. | Acts as the **Incident Commander**: approves high-risk actions on Tier-0 assets and audits decisions. | Modern Agentic SOCs (**AgentSOC**, **Vigil**, **Dropzone**, **LanG**). |
| **L4** | **High Autonomy** | Autonomous end-to-end detection, counterfactual hypothesis falsification, blast-radius containment, and post-incident rule creation. | Passive supervisor: reviews weekly audit ledgers and sets broad security policies. | Emerging Academic Prototypes. |
| **L5** | **Full Autonomy** | System dynamically discovers novel zero-day attack campaigns across global telemetry, autonomously mutates defenses. | Strategic governance and regulatory reporting. | Theoretical Long-Term Horizon. |

---

## 3. The 4 Functional Phases of an Agentic SOC

The survey systematically maps LLM implementations across the **four lifecycle phases** of a security incident:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. DETECTION & INGESTION PHASE                                              │
│ • Semantic log tokenization (OCSF normalization)                            │
│ • Embedding-based anomaly detection vs. statistical thresholding            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ 2. TRIAGE & FILTERING PHASE                                                 │
│ • False-positive suppression using Counterfactual Reasoning                 │
│ • Contextual alert deduplication (clustering 1,000 alerts into 1 campaign)  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ 3. DEEP INVESTIGATION & CORRELATION PHASE                                   │
│ • Syntax-Constrained Query Modeling (SQM) for KQL/SPL execution             │
│ • Graph of Thought (GoT) attack-tree reconstruction across MITRE ATT&CK     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ 4. CONTAINMENT & POST-MORTEM PHASE                                          │
│ • Blast-radius simulation enforcing the "Rule of Zero"                      │
│ • Autonomous synthesis of verified defensive rules (Sigma, YARA, Snort)     │
│ • Cryptographic decision logging for compliance (SOC 2, ISO 27001)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Human-AI Collaboration & The "Automation Bias" Danger

One of the survey's most critical contributions is analyzing the **psychological and operational pitfalls** of pairing human analysts with highly capable autonomous agents:

### 1. Automation Bias & Skill Atrophy
When an AI agent is accurate 95% of the time, human analysts become conditioned to trust it blindly. In field studies:
* Junior analysts stopped reading underlying forensic logs.
* Analysts approved incorrect verdicts because *"the AI generated a very convincing, polished 3-paragraph summary"*.
* Over time, junior analysts' investigative skills degraded because they never performed manual queries.

### 2. The Solution: Replayable Decision Ledgers
To counter automation bias, the survey mandates that autonomous SOC platforms must **never output a single "black-box" paragraph**. Instead, platforms must generate a **Cryptographic Decision Ledger**:
* Every reasoning step, input hash, and tool result must be recorded in an auditable chain (e.g., as implemented in [`agents/decision_ledger.py`](file:///c:/Agentic%20SOC/agents/decision_ledger.py)).
* The human analyst is presented with a structured **Evidence Matrix** rather than just a conclusion, allowing the human to verify the agent's logic in under 30 seconds.

---

## 5. Layman's Analogy: The Self-Driving Car Evolution

| Self-Driving Car Evolution | Autonomous SOC Equivalent |
| :--- | :--- |
| **1990: Manual Transmission Car**<br>The driver controls steering, clutch, brakes, and headlights. | **Level 0 (Manual SIEM)**<br>The analyst reads raw log lines, types SQL queries by hand, and writes manual tickets. |
| **2005: Cruise Control**<br>Maintains a fixed speed on the highway, but crashes if traffic stops ahead. | **Level 1 (Legacy SOAR)**<br>Runs a fixed script (*"If alert = Phishing, delete email"*), but breaks if the email format changes. |
| **2016: Lane Centering & Blind-Spot Warnings**<br>Car beeps when you drift, but driver must keep hands on the wheel. | **Level 2 (AI Copilot)**<br>AI drafts a summary of the alert on screen, but the human must click every button to investigate. |
| **2024: Highway Autopilot (Tesla / Waymo / Mercedes Level 3)**<br>Car steers, changes lanes, and brakes automatically. Driver must take over if construction appears. | **Level 3 (Current Agentic SOC)**<br>AI investigates 100% of alerts, isolates malware on laptops automatically, but requests human approval before touching core servers. |
| **2030+: Fully Driverless Robotaxi with No Steering Wheel**<br>Vehicle operates in all weather without a human driver in the cabin. | **Level 5 (Theoretical Autonomous SOC)**<br>Enterprise network self-heals, isolates attacks, rewrites firewall rules, and creates zero-day signatures automatically. |

---

## 6. Key Conclusions & Open Frontiers from the Survey

1. **The Shift from Chatbots to Agent Teams**: Chat interfaces (like asking an LLM a question) are inadequate for SOC work. Security requires **autonomous multi-agent graphs** that interact through standardized tool protocols like **MCP**.
2. **Context Window Limits**: Analyzing attacks that develop slowly over 6 months generates gigabytes of logs, requiring hierarchical vector memory and graph databases rather than raw context stuffing.
3. **Formal Governance**: Autonomous containment will only gain widespread enterprise adoption when platforms implement formal verification, blast-radius simulation, and mathematical non-repudiation.
