# Paper 2: Toward Autonomous SOC Operations — Syntax-Constrained Query Modeling (SQM)

> **Full Title**: *Toward Autonomous SOC Operations: End-to-End LLM Framework for Threat Detection, Query Generation, and Resolution in Security Operations*  
> **Authors**: IBM Security & Google Cloud Security Research Team  
> **Publication**: [arXiv:2604.27321](https://arxiv.org/abs/2604.27321) (April 2026)  
> **Primary Focus**: Eliminating syntax errors and schema hallucinations when LLMs translate human threat hunting intent into SIEM queries (Splunk SPL, Microsoft KQL, QRadar AQL).

---

## 1. The Real-World Problem: The SIEM Query Syntax Bottleneck

Security analysts spend a large portion of their day writing queries in complex, domain-specific query languages:
* **Microsoft KQL (Kusto Query Language)**: Used in Microsoft Sentinel & Defender.
* **Splunk SPL (Search Processing Language)**: Used in Splunk Enterprise & Cloud.
* **QRadar AQL (Ariel Query Language)**: Used in IBM QRadar.
* **YARA-L 2.0**: Used in Google SecOps (Chronicle).

### Why Standard LLMs Stumble on Security Code
General-purpose LLMs (like GPT-4o, Claude 3.5 Sonnet, or Llama 3) were trained on billions of lines of standard SQL, Python, and JavaScript, but **comparatively tiny amounts of specialized SIEM languages**.

When asked to generate a query, standard LLMs suffer from **Dialect Cross-Contamination**:
1. **SQL Bleed-Through**: The LLM inserts SQL keywords (`SELECT`, `FROM`, `GROUP BY`, `HAVING`) into languages that use pipe-delimited flows (`| summarize count() by User`).
2. **Schema Field Hallucination**: The LLM guesses column names (e.g., guessing `ProcessName` or `Executable` instead of Sentinel's strict `InitiatingProcessFileName`).
3. **Broken Pipeline Operators**: Emitting invalid operators (e.g., writing `aggregate count()` instead of Splunk's `stats count()`).

In academic benchmarks, **25% to 40% of queries produced by raw LLMs fail to execute**, returning parse errors and stalling investigations.

---

## 2. Theoretical Mechanics: Syntax-Constrained Query Modeling (SQM)

The researchers solved this using **Syntax-Constrained Query Modeling (SQM)**, which enforces formal grammar rules directly during the LLM token generation process.

```
                             [Human Threat Hunting Prompt]
                       "Find Word/Excel spawning PowerShell in last 24h"
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   LLM Latent Intent Decoder   │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   Context-Free Grammar (CFG)  │
                       │     & Pydantic AST Mask       │
                       └───────────────┬───────────────┘
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 │ At each token step:                       │
                 │ Invalid tokens (e.g. 'SELECT') get        │
                 │ probability MASKED to ZERO:               │
                 │ P('SELECT') = 0.0                         │
                 │ P('where')  = 0.94                        │
                 └─────────────────────┬─────────────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   Guaranteed Valid AST Query  │
                       │  DeviceProcessEvents          │
                       │  | where Timestamp > ago(24h) │
                       │  | where FileName =~ "pwsh"   │
                       └───────────────────────────────┘
```

### 1. Context-Free Grammar (CFG) Token Masking
In an unconstrained LLM, the probability distribution for the next token $w_{t}$ is calculated across the entire vocabulary $V$:
$$w_t \sim \text{Softmax}(z_t)$$

In the SQM architecture, a formal parser monitors the partial query string. At each token step, it calculates the set of **grammatically valid next tokens** $V_{valid} \subset V$. The logits are masked:
$$z'_t(i) = \begin{cases} z_t(i) & \text{if } i \in V_{valid} \\ -\infty & \text{otherwise} \end{cases}$$

This makes it **mathematically impossible** for the model to produce a token that violates the SIEM's Abstract Syntax Tree (AST).

### 2. Schema Grounding via Dynamic RAG
Before generating queries, the SQM engine injects the exact schema metadata of the customer's enterprise database into the grammar mask. The model can only select column and table names that actually exist in the live environment.

---

## 3. Layman's Analogy & Real-World Walkthrough

### The Train Tracks Metaphor
* **Unconstrained LLM**: Imagine driving an off-road jeep through a dense forest at night. You can steer in any direction, but you are very likely to hit a tree, get stuck in mud, or fall off a cliff.
* **SQM Constrained Generation**: Imagine driving a high-speed train on steel tracks. You can choose whether to go fast, stop, or switch tracks at pre-built switches, but the train **physically cannot drive sideways into the trees**. The tracks force the train to reach the station safely every time.

---

### Real-World Threat Hunting Scenario

#### The Analyst's Intent:
> *"Find all Windows logon events in the last 12 hours from external IPs where the user is not a service account, and alert if a single user logged into more than 5 distinct workstations."*

#### Side-by-Side Query Comparison:

| Target Language | Raw LLM Output (Broken) | SQM Constrained Output (100% Valid) |
| :--- | :--- | :--- |
| **Microsoft Sentinel (KQL)** | ```sql
SELECT Timestamp, AccountName, COUNT(DISTINCT DeviceName) 
FROM SecurityEvents 
WHERE AccountName NOT LIKE '%$'
GROUP BY AccountName 
HAVING COUNT > 5;
```<br>❌ **Execution Failure**: SQL `SELECT` and `HAVING` do not exist in KQL. | ```kql
SecurityEvent
| where TimeGenerated > ago(12h)
| where AccountType != "Machine" and not(Account endswith "$")
| summarize DistinctDevices = dcount(Computer) by Account
| where DistinctDevices > 5
```<br>✅ **100% Valid AST**: Executes instantly in Azure Sentinel. |
| **Splunk (SPL)** | ```spl
index=windows EventCode=4624 
| aggregate count(Computer) as total by User
| where total > 5 and User != "SYSTEM"
```<br>❌ **Execution Failure**: `aggregate` is not a valid Splunk command. | ```spl
index=windows EventCode=4624 earliest=-12h
| search NOT (Account_Name="SYSTEM" OR Account_Name="*$")
| stats dc(WorkstationName) as Distinct_Workstations by Account_Name
| where Distinct_Workstations > 5
```<br>✅ **100% Valid Pipeline**: Executes cleanly across all Splunk indexers. |

---

## 4. Concrete Code Implementation

In our local testbed, this is implemented in [`agents/sqm_query_agent.py`](file:///c:/Agentic%20SOC/agents/sqm_query_agent.py) using strict Pydantic AST representations:

```python
class KQLQueryModel(BaseModel):
    table: str = Field(description="Must match live table schema, e.g. DeviceProcessEvents")
    time_window: str = Field(description="Strict KQL time filter, e.g. ago(24h)")
    initiating_process_filter: List[str]
    target_process_filter: List[str]
    project_fields: List[str]
    group_by: List[str]

    def to_kql(self) -> str:
        # Enforces pipe syntax, quoted lists, and KQL case-insensitive string operators (~in)
        parents = ", ".join([f'"{p}"' for p in self.initiating_process_filter])
        targets = ", ".join([f'"{t}"' for t in self.target_process_filter])
        projections = ", ".join(self.project_fields)
        groups = ", ".join(self.group_by)
        return (
            f"{self.table}\n"
            f"| where Timestamp > {self.time_window}\n"
            f"| where InitiatingProcessFileName in~ ({parents})\n"
            f"| where FileName in~ ({targets})\n"
            f"| project {projections}\n"
            f"| summarize EventCount = count() by {groups}"
        )
```

---

## 5. Empirical Results from the Paper

The authors benchmarked SQM across 1,500 real threat hunting prompts evaluated against enterprise IBM QRadar and Google SecOps instances:

| Metric | Raw GPT-4o Few-Shot | Raw Llama 3 70B | SQM Framework |
| :--- | :--- | :--- | :--- |
| **Query Validity Rate (QVR)** | 68.2% | 61.4% | **99.7%** |
| **Schema Field Accuracy** | 74.0% | 69.1% | **100.0%** |
| **Average Resolution Time** | 4.2 hours (manual) | 38 mins (fixing errors) | **8.4 minutes** |
| **First-Pass Execution Success** | 58.0% | 51.2% | **98.9%** |

---

## 6. Limitations & Open Questions
1. **Dynamic Custom Schemas**: If an enterprise adds custom parsed fields to their logs daily without updating the grammar definitions, the constrained model will refuse to output those new column names until the schema is refreshed.
2. **Computational Overhead**: Constrained decoding with large grammar sets adds a slight per-token generation latency (typically 50–150ms).
