# Agentic SOC: Autonomous Security Operations & Academic Benchmark Testbed

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ollama: Ready](https://img.shields.io/badge/Ollama-Offline%20Local%20Models-purple.svg)](https://ollama.com)
[![Architecture: Multi--Agent](https://img.shields.io/badge/Architecture-Agentic%20SOC-green.svg)](#multi-agent-architecture)

An open-source, reproducible evaluation testbed implementing and benchmarking the **5 core academic hypotheses** of **Agentic Security Operations Centers (SOCs)** (grounded in research from *AgentSOC*, *Toward Autonomous SOC Operations*, *LanG*, *AiSOC*, and *AgenticCyOps*).

---

## 📌 Executive Summary

Legacy SIEM and deterministic SOAR playbooks rely on brittle, static IF-THEN logic that breaks when adversaries use living-off-the-land techniques or polymorphic payloads. An **Agentic SOC** replaces static DAGs with **autonomous cognitive multi-agent loops** capable of dynamic tool calling (via the Model Context Protocol - MCP), counterfactual hypothesis falsification, and blast-radius-aware containment.

```
                       ┌─────────────────────────┐
                       │   Ingested Telemetry    │
                       │ (Sysmon, EDR, Cloud, NW)│
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │  Triage Agent (Tier 1)  │◄── Normalized Schema (OCSF)
                       │ Deduplication & Noise   │
                       └────────────┬────────────┘
                                    │ (Escalate True Positives)
                                    ▼
                     ┌──────────────────────────────┐
                     │   SOC Lead / Coordinator     │
                     │  Agentic Graph Orchestrator  │
                     └──────┬──────────────┬────────┘
                            │              │
            ┌───────────────┘              └────────────────┐
            ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│  Forensics Agent (DFIR) │                     │   Threat Intel Agent    │
│  • Memory & Process     │                     │  • IOC Enrichment       │
│  • Timeline Analysis    │                     │  • Threat Actor Mapping │
│  • Artifact Extraction  │                     │  • ATT&CK Correlation   │
└───────────┬─────────────┘                     └───────────┬─────────────┘
            │                                               │
            └───────────────┐              ┌────────────────┘
                            ▼              ▼
                     ┌──────────────────────────────┐
                     │ Hypothesis & Synthesis Agent │
                     │ • Attack Tree Reconstruction │
                     │ • Root Cause Identification  │
                     └──────────────┬───────────────┘
                                    │
                                    ▼
                     ┌──────────────────────────────┐
                     │   Safety & Guardrail Engine  │
                     │   ("Rule of Zero" & Policy)  │
                     └──────────────┬───────────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 │                                     │
                 ▼ (High Risk Action)                  ▼ (Low Risk / Auto-Ops)
      ┌──────────────────────┐              ┌──────────────────────┐
      │  Human-in-the-Loop   │              │ Autonomous Response  │
      │  (Analyst Sign-off)  │              │ (Block IP, Revoke)   │
      └──────────────────────┘              └──────────────────────┘
```

---

## 🔬 The 5 Academic Hypotheses & Empirical Findings

| Hypothesis | Academic Source | Baseline Limitation | Agentic SOC Innovation | Testbed Finding |
| :--- | :--- | :--- | :--- | :---: |
| **H1: Counterfactual Triage** | *AgentSOC* (Roy et al., IEEE 2026) | **Confirmation Bias**: Flags benign admin patch scripts as critical attacks ($FPR \approx 100\%$). | **Dual-Hypothesis Falsification**: Proactively seeks negative proof (change tickets, certificates). | **$FPR \to 0.0\%$** |
| **H2: Syntax-Constrained Querying (SQM)** | *Toward Autonomous SOC* (arXiv 2026) | **Syntax Hallucinations**: Emits invalid SQL clauses (`SELECT`, `GROUP BY`) inside KQL/SPL ($QVR \approx 33\%$). | **Grammar-Guided ASTs**: Enforces Pydantic/CFG constraints during decoding. | **$QVR \to 100.0\%$** |
| **H3: Blast Radius & Rule of Zero** | *LanG* / *AgentSOC* (arXiv 2026) | **Operational Outage**: Blindly isolates Active Directory Domain Controllers during alarms ($0\%$ safety). | **Dependency Graph Simulation**: Evaluates downtime costs; enforces Human-in-the-Loop on Tier-0/1 assets. | **$100\%$ Outage Protection** |
| **H4: Telemetry Injection Resilience** | *AgenticCyOps* (arXiv 2026) | **Prompt Hijacking**: Malicious instructions in HTTP User-Agents bypass triage ($ASR \approx 100\%$). | **OCSF Schema Isolation**: Isolates untrusted telemetry in structured, parameterized data blocks. | **$ASR \to 0.0\%$** |
| **H5: Replayable Decision Ledgers** | *AiSOC* / *SIRP Labs* (2025–2026) | **Opaque Black Box**: Chat transcripts are non-verifiable and non-reproducible for SOC 2 audits. | **Cryptographic State Chain**: SHA-256 state ledger proves non-repudiation and enables forensic replay. | **$100\%$ Cryptographic Non-Repudiation** |

---

## 📂 Repository Structure

```
.
├── AGENTIC_SOC_COMPREHENSIVE_RESEARCH_AND_TESTBED.md  # Deep research survey & full documentation
├── run_all_benchmarks.py                              # Master automated benchmark runner
├── benchmark_results.json                             # Recorded empirical test scores
│
├── data/                                              # Ground-truth security datasets
│   ├── benign_admin_tasks.json                        # SCCM patch loops & emergency maintenance
│   ├── lateral_movement_psexec.json                   # Office macros & NTDS.dit credential dumping
│   ├── enterprise_asset_graph.json                    # Enterprise topology (Tier-0 DCs, Tier-1 APIs)
│   ├── poisoned_telemetry.json                        # Adversarial logs with indirect prompt injections
│   └── natural_language_hunt_prompts.json             # Threat hunting prompts for KQL, SPL & Sigma
│
├── agents/                                            # Autonomous Agent Architectures
│   ├── llm_backend.py                                 # Dual-target: Live Ollama + Deterministic Fallback
│   ├── baseline_react_agent.py                        # Industry baseline ReAct agent
│   ├── counterfactual_agent.py                        # H1: Narrative counterfactual reasoner
│   ├── sqm_query_agent.py                             # H2: Syntax-Constrained Query Modeling compiler
│   ├── safety_guardrail_engine.py                     # H3: Blast-radius simulator (Rule of Zero)
│   ├── secure_telemetry_parser.py                     # H4: OCSF schema isolation & injection filter
│   └── decision_ledger.py                             # H5: Cryptographic state-transition ledger
│
├── tools/                                             # Mock Security & Infrastructure Services
│   └── mock_security_tools.py                         # VirusTotal, AbuseIPDB, CMDB & KQL/SPL AST parsers
│
├── demos/                                             # Interactive CLI Demos for each Hypothesis
│   ├── demo_h1_counterfactual.py                      # Demo H1: Counterfactual reasoning
│   ├── demo_h2_sqm.py                                 # Demo H2: Syntax-constrained querying
│   ├── demo_h3_blast_radius.py                        # Demo H3: Blast radius & Domain Controller defense
│   ├── demo_h4_prompt_injection.py                    # Demo H4: Indirect prompt injection defense
│   └── demo_h5_decision_ledger.py                     # Demo H5: Cryptographic audit ledger & replay
│
└── eval/                                              # Evaluation Suite & Mathematical Scoring
    ├── metrics.py                                     # FPR, FNR, QVR, ASR & Safety Score formulas
    └── benchmark_runner.py                            # Batch evaluation runner
```

---

## 🚀 Quick Start

### 1. Prerequisites
* Python 3.10, 3.11, or 3.12
* [Optional] [Ollama](https://ollama.com/) for running local offline models (`qwen2.5:0.5b`, `llama3`, `mistral`). If Ollama is not installed or running, the testbed automatically uses the built-in **Deterministic Local Reasoning Engine**.

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/<your-username>/agentic-soc.git
cd agentic-soc

# Create virtual environment
python -m venv .venv

# Activate environment (Windows PowerShell)
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Master Benchmark Suite
```bash
python run_all_benchmarks.py
```

---

## 🎮 Running Individual Hypothesis Demos

Each hypothesis can be demonstrated interactively in isolation:

```bash
# 1. Counterfactual Triage vs. Naive ReAct (False-Positive Suppression)
python demos/demo_h1_counterfactual.py

# 2. Syntax-Constrained Query Modeling (KQL, SPL, Sigma)
python demos/demo_h2_sqm.py

# 3. Blast-Radius Simulation & Rule of Zero (Domain Controller Protection)
python demos/demo_h3_blast_radius.py

# 4. Indirect Prompt Injection Defense via OCSF Schema Isolation
python demos/demo_h4_prompt_injection.py

# 5. Cryptographic Replayable Decision Ledger & Tamper Detection
python demos/demo_h5_decision_ledger.py
```

---

## 🤖 Model Backends: Offline Simulation vs. Live Ollama

The backend (`agents/llm_backend.py`) provides seamless dual-mode execution:

### Mode 1: Deterministic Local Reasoning Engine (Zero Setup)
Default offline mode. Operates in-memory in pure Python with zero GPU or network requirements, reproducing standard baseline errors and agentic defenses.

### Mode 2: Live Local Models via Ollama
To test against a real local LLM:
```bash
# Start Ollama
ollama run qwen2.5:0.5b
# or: ollama run llama3

# Run the benchmark suite against your local model
python run_all_benchmarks.py
```
To select a specific model:
```bash
# Windows PowerShell
$env:OLLAMA_MODEL = "qwen2.5:0.5b"
python run_all_benchmarks.py

# Linux / macOS
export OLLAMA_MODEL="qwen2.5:0.5b"
python run_all_benchmarks.py
```

---

## 📚 Comprehensive Documentation
For the complete 10,000-word survey covering commercial platforms (Dropzone AI, Torq Socrates, Prophet Security, Intezer), direct video demos, and academic literature analysis, see:
👉 [**`AGENTIC_SOC_COMPREHENSIVE_RESEARCH_AND_TESTBED.md`**](AGENTIC_SOC_COMPREHENSIVE_RESEARCH_AND_TESTBED.md)

---

## 📜 License
This project is open-source and released under the [MIT License](LICENSE).
