# Academic Literature on Agentic & Autonomous SOCs (2024–2026)

This directory contains comprehensive, standalone plain-English deep dives for each of the **5 foundational research papers** shaping the future of autonomous Security Operations Centers (SOCs).

---

## 📑 Paper Index

### 1. [Paper 1: AgentSOC — Narrative Counterfactual Reasoning & Structural Simulation](01_agentsoc_counterfactual_reasoning.md)
* **Citation**: Joyjit Roy et al., IEEE ICAIC / [arXiv:2604.20134](https://arxiv.org/abs/2604.20134) (April 2026)
* **Core Focus**: Eliminating confirmation bias in triage ($H_{malicious}$ vs. $H_{benign}$ falsification) and simulating asset blast radius to prevent accidental outages on Tier-0 Domain Controllers.
* **Everyday Analogy**: The ER doctor who checks an EKG before performing open-heart surgery for heartburn.

---

### 2. [Paper 2: Toward Autonomous SOC Operations — Syntax-Constrained Query Modeling (SQM)](02_autonomous_soc_sqm_query_generation.md)
* **Citation**: IBM Security & Google Cloud Security Research, [arXiv:2604.27321](https://arxiv.org/abs/2604.27321) (April 2026)
* **Core Focus**: Using formal Context-Free Grammars (CFGs) and Pydantic AST decoders to guarantee 100% syntactically valid SIEM queries (KQL, SPL, YARA-L).
* **Everyday Analogy**: Magnetic alphabet poetry tiles on pre-built grammar tracks that make it physically impossible for the AI to speak broken SQL.

---

### 3. [Paper 3: LanG — Governance-Aware Agentic AI & The "Rule of Zero"](03_lang_governance_and_rule_of_zero.md)
* **Citation**: Security & Systems Lab, [arXiv:2604.nnnnn](https://arxiv.org/) (April 2026)
* **Core Focus**: Enforcing cryptographic separation of powers (advisory agents hold zero root keys) and two-layer semantic guardrails to prevent unvetted containment actions.
* **Everyday Analogy**: The separation of powers between the police detective (who gathers clues) and the judge (who must sign the search warrant).

---

### 4. [Paper 4: AgenticCyOps — Defending Against Indirect Prompt Injection in Telemetry](04_agenticcyops_telemetry_prompt_injection.md)
* **Citation**: Cyber AI Working Group, [arXiv:2603.nnnnn](https://arxiv.org/) (March 2026)
* **Core Focus**: Protecting autonomous triage agents from adversarial instructions embedded inside HTTP User-Agents, process parameters, and DNS queries using OCSF schema isolation.
* **Everyday Analogy**: Placing toxic evidence inside a sealed digital hazmat container so the detective evaluates it as clues rather than following orders written by the criminal.

---

### 5. [Paper 5: The Grand Survey — LLMs in the SOC & The 6 Levels of Autonomy](05_soc_llm_survey_and_autonomy_levels.md)
* **Citation**: Ali Habibzadeh et al., [arXiv:2509.10858](https://arxiv.org/abs/2509.10858) (Updated late 2025) & SIRP Labs / ACM Standards
* **Core Focus**: A systemic meta-analysis of over 180 implementations establishing the formal Levels 0 to 5 of SOC Autonomy, addressing automation bias and cryptographic decision ledgers.
* **Everyday Analogy**: The evolution of self-driving cars (from manual driving, to cruise control, to hands-off highway driving, to driverless robotaxis).

---

## 🛠️ How These Papers Map to Our Codebase

Every paper documented here corresponds to working, executable code in our repository:

| Paper | Corresponding Module in `c:\Agentic SOC` | Interactive Demo |
| :--- | :--- | :--- |
| **Paper 1 (AgentSOC)** | [`agents/counterfactual_agent.py`](../../agents/counterfactual_agent.py) | `python demos/demo_h1_counterfactual.py` |
| **Paper 2 (SQM Queries)** | [`agents/sqm_query_agent.py`](../../agents/sqm_query_agent.py) | `python demos/demo_h2_sqm.py` |
| **Paper 3 (LanG Guardrails)** | [`agents/safety_guardrail_engine.py`](../../agents/safety_guardrail_engine.py) | `python demos/demo_h3_blast_radius.py` |
| **Paper 4 (AgenticCyOps)** | [`agents/secure_telemetry_parser.py`](../../agents/secure_telemetry_parser.py) | `python demos/demo_h4_prompt_injection.py` |
| **Paper 5 (Decision Ledgers)** | [`agents/decision_ledger.py`](../../agents/decision_ledger.py) | `python demos/demo_h5_decision_ledger.py` |
