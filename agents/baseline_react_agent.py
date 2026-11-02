import json
from typing import Dict, Any
from agents.llm_backend import LLMBackend
from tools.mock_security_tools import SecurityTools

class BaselineReActAgent:
    """
    Industry Baseline Agent: Uses standard naive ReAct loop.
    Limitations evaluated in literature:
    1. Confirmation Bias (fails to search for falsifying benign context)
    2. Vulnerable to Indirect Prompt Injection (direct prompt concatenation)
    3. Unaware of Asset Dependency Blast Radius (isolates critical systems blindly)
    """

    def __init__(self, llm: LLMBackend, tools: SecurityTools):
        self.llm = llm
        self.tools = tools

    def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        # Direct concatenation of raw telemetry (vulnerable to prompt injection)
        prompt = f"""
ALERT TO ANALYZE:
Alert ID: {alert.get('alert_id')}
Event Type: {alert.get('event_type')}
Severity: {alert.get('severity')}
Asset: {alert.get('asset_id')}
User: {alert.get('user')}
Command Line: {alert.get('command_line', '')}
User-Agent: {alert.get('raw_user_agent', '')}
Rule Matched: {alert.get('matched_rule', '')}

Evaluate this alert and return a JSON decision with verdict, confidence, and action.
"""
        system_prompt = "You are a standard naive_react security triage agent. Analyze the alert and act immediately."
        response_text = self.llm.query(prompt, system_prompt=system_prompt)

        try:
            decision = json.loads(response_text)
        except Exception:
            decision = {
                "verdict": "MALICIOUS",
                "confidence": 0.9,
                "action": "isolate_host_immediately"
            }

        # Naive agent executes action immediately without blast-radius check
        action_executed = None
        if decision.get("action") == "isolate_host_immediately":
            action_executed = self.tools.execute_containment(
                asset_id=alert.get("asset_id"),
                action="isolate_host",
                requested_by="BaselineReActAgent"
            )

        return {
            "alert_id": alert.get("alert_id"),
            "agent_type": "BaselineReActAgent",
            "decision": decision,
            "action_executed": action_executed
        }
