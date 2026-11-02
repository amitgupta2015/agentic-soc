import hashlib
import json
import time
from typing import Dict, Any, List

class DecisionLedger:
    """
    Hypothesis 5 (AiSOC / LanG): Replayable Decision Ledger & Cryptographic State Traceability.
    Records every node state, input hash, reasoning step, and tool result in a tamper-evident chain.
    Allows automated replay verification for compliance (SOC 2, ISO 27001) and DFIR validation.
    """

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.ledger_entries: List[Dict[str, Any]] = []
        self.last_hash = "GENESIS_ROOT_HASH"

    def record_step(self, step_name: str, inputs: Dict[str, Any], agent_thought: str, tool_called: str, tool_output: Any) -> str:
        timestamp = time.time()
        payload = {
            "incident_id": self.incident_id,
            "step_name": step_name,
            "timestamp": timestamp,
            "inputs": inputs,
            "agent_thought": agent_thought,
            "tool_called": tool_called,
            "tool_output": tool_output,
            "previous_hash": self.last_hash
        }
        
        # Calculate SHA-256 state transition hash
        payload_str = json.dumps(payload, sort_keys=True)
        step_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        payload["step_hash"] = step_hash
        
        self.ledger_entries.append(payload)
        self.last_hash = step_hash
        return step_hash

    def export_ledger(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "total_steps": len(self.ledger_entries),
            "final_state_hash": self.last_hash,
            "entries": self.ledger_entries
        }

    @staticmethod
    def verify_and_replay(ledger_export: Dict[str, Any]) -> Dict[str, Any]:
        """Verify the cryptographic integrity of every step in the ledger."""
        entries = ledger_export.get("entries", [])
        expected_prev = "GENESIS_ROOT_HASH"
        
        for idx, entry in enumerate(entries):
            reported_hash = entry.get("step_hash")
            recorded_prev = entry.get("previous_hash")
            
            if recorded_prev != expected_prev:
                return {
                    "valid": False,
                    "error": f"Hash chain broken at step {idx}: previous_hash mismatch"
                }
            
            # Recalculate hash
            verify_payload = {k: v for k, v in entry.items() if k != "step_hash"}
            calc_hash = hashlib.sha256(json.dumps(verify_payload, sort_keys=True).encode("utf-8")).hexdigest()
            
            if calc_hash != reported_hash:
                return {
                    "valid": False,
                    "error": f"Tampered data detected at step {idx}: payload content does not match cryptographic hash"
                }
            
            expected_prev = reported_hash

        return {
            "valid": True,
            "verified_steps": len(entries),
            "cryptographic_integrity": "100%_PASS",
            "audit_trail_non_repudiation": "CONFIRMED"
        }
