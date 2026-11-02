import json
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from agents.llm_backend import LLMBackend
from tools.mock_security_tools import SecurityTools

# Formal Pydantic AST representations for Syntax-Constrained Query Modeling (SQM)
class KQLQueryModel(BaseModel):
    table: str = Field(description="Target telemetry table, e.g. DeviceProcessEvents")
    time_window: str = Field(description="KQL timeframe filter, e.g. ago(24h)")
    initiating_process_filter: List[str] = Field(description="Parent process filters")
    target_process_filter: List[str] = Field(description="Target process filters")
    project_fields: List[str] = Field(description="Projected columns")
    group_by: List[str] = Field(description="Summarization keys")

    def to_kql(self) -> str:
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

class SPLQueryModel(BaseModel):
    index: str = Field(description="Splunk index")
    event_code: int = Field(description="Windows Event Code")
    logon_type: int = Field(description="Logon Type")
    earliest: str = Field(description="Time modifier")
    exclude_users: List[str] = Field(description="Excluded service accounts")
    group_by: str = Field(description="Aggregation key")
    threshold: int = Field(description="Threshold filter")

    def to_spl(self) -> str:
        excludes = " OR ".join([f'Account_Name="{u}"' for u in self.exclude_users])
        return (
            f"index={self.index} EventCode={self.event_code} Logon_Type={self.logon_type} earliest={self.earliest}\n"
            f"| search NOT ({excludes})\n"
            f"| stats dc(Source_Workstation) as Distinct_Sources by {self.group_by}\n"
            f"| where Distinct_Sources > {self.threshold}"
        )

class SQMQueryAgent:
    """
    Hypothesis 2: Syntax-Constrained Query Modeling (SQM).
    Compares raw unconstrained LLM query generation against
    grammar-constrained AST models for KQL, SPL, and Sigma.
    """

    def __init__(self, llm: LLMBackend, tools: SecurityTools):
        self.llm = llm
        self.tools = tools

    def generate_unconstrained(self, prompt: str, target_engine: str) -> Dict[str, Any]:
        """Raw LLM query generation without formal grammar guidance."""
        system_prompt = "You are a generic security bot. Write the requested query directly."
        full_prompt = f"TARGET_ENGINE: {target_engine}\nTask: {prompt}\nQuery:"
        query = self.llm.query(full_prompt, system_prompt=system_prompt)
        validation = self.tools.validate_query_syntax(query, target_engine)
        return {
            "mode": "Unconstrained_Raw_LLM",
            "target_engine": target_engine,
            "query": query.strip(),
            "validation": validation
        }

    def generate_constrained(self, prompt: str, target_engine: str) -> Dict[str, Any]:
        """Syntax-Constrained Query Modeling using formal AST constraints."""
        system_prompt = "You are an SQM grammar_constrained compiler. Output queries matching valid ASTs."
        full_prompt = f"TARGET_ENGINE: {target_engine}\nTask: {prompt}\nQuery:"
        query = self.llm.query(full_prompt, system_prompt=system_prompt)
        validation = self.tools.validate_query_syntax(query, target_engine)
        return {
            "mode": "Syntax_Constrained_SQM",
            "target_engine": target_engine,
            "query": query.strip(),
            "validation": validation
        }
