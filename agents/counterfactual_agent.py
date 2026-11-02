import json
from typing import Dict, Any, List
from agents.llm_backend import LLMBackend
from tools.mock_security_tools import SecurityTools

class CounterfactualAgent:
    """
    Hypothesis 1 (AgentSOC): Narrative Counterfactual Reasoning Engine.
    Actively constructs competing hypotheses (Malicious vs Benign Alternative)
    and queries for falsifying evidence before confirming an alert.
    """

    def __init__(self, llm: LLMBackend, tools: SecurityTools):
        self.llm = llm
        self.tools = tools

    def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = alert.get("alert_id")
        context = alert.get("context", {})
        
        # Step 1: Active Falsification Query Loop
        # Agent searches for alternative explanations:
        # - Is there an active ITSM Change Request for this activity?
        # - Is the binary digitally signed by a trusted vendor?
        # - Is the source IP internal or known benign?
        falsification_evidence = []
        
        ticket_id = context.get("change_ticket_id")
        if ticket_id:
            ticket_info = self.tools.lookup_change_ticket(ticket_id)
            if ticket_info.get("found"):
                falsification_evidence.append(f"Verified Change Ticket: {ticket_id} ({ticket_info['details']['description']})")

        if context.get("digital_signature") and "Verified" in context.get("digital_signature"):
            falsification_evidence.append(f"Cryptographic Signature Valid: {context['digital_signature']}")

        if context.get("parent_is_trusted_service"):
            falsification_evidence.append("Parent Process is verified enterprise daemon/service.")

        # Step 2: Query Counterfactual Reasoner with evidence balance
        prompt = f"""
ALERT UNDER COUNTERFACTUAL ANALYSIS:
Alert ID: {alert_id}
Event Type: {alert.get('event_type')}
Asset: {alert.get('asset_id')}
Command: {alert.get('command_line') or alert.get('decoded_command')}
Matched Detection: {alert.get('matched_rule')}

DISCOVERED FALSIFICATION CONTEXT:
{json.dumps(falsification_evidence, indent=2)}

Task:
Formulate Hypothesis A (Attacker Action) vs Hypothesis B (Legitimate Admin Action).
Weigh the evidence and determine whether the alert should be confirmed as MALICIOUS or auto-suppressed as BENIGN.
Output JSON only.
"""
        system_prompt = "You are an agentic counterfactual reasoning engine. You weigh competing hypotheses and demand falsification proof."
        response_text = self.llm.query(prompt, system_prompt=system_prompt)

        try:
            decision = json.loads(response_text)
        except Exception:
            decision = {
                "final_verdict": "BENIGN" if falsification_evidence else "MALICIOUS",
                "falsification_evidence": falsification_evidence
            }

        return {
            "alert_id": alert_id,
            "agent_type": "CounterfactualAgent",
            "competing_hypotheses": decision,
            "falsification_evidence_found": len(falsification_evidence),
            "final_verdict": decision.get("final_verdict", "MALICIOUS")
        }
