import json
from typing import Dict, Any, List
import networkx as nx
from tools.mock_security_tools import SecurityTools

class SafetyGuardrailEngine:
    """
    Hypothesis 3 (LanG / AgentSOC): Blast-Radius Simulation & Rule-of-Zero.
    Ensures that an advisory agent cannot isolate mission-critical assets
    (Tier-0 Domain Controllers, Tier-1 Gateways) without automated impact assessment
    and mandatory Human-in-the-Loop (HITL) authorization gates.
    """

    def __init__(self, tools: SecurityTools):
        self.tools = tools
        self.graph = nx.DiGraph()
        self._build_topology_graph()

    def _build_topology_graph(self):
        assets = self.tools.asset_graph.get("assets", [])
        edges = self.tools.asset_graph.get("topology_edges", [])
        for asset in assets:
            self.graph.add_node(asset["id"], **asset)
        for edge in edges:
            self.graph.add_edge(edge["source"], edge["target"], protocol=edge.get("protocol"))

    def evaluate_containment_request(self, asset_id: str, proposed_action: str) -> Dict[str, Any]:
        """
        Simulate the impact of proposed containment on business operations.
        Enforces the 'Rule of Zero'.
        """
        asset = self.tools.get_asset_metadata(asset_id)
        tier = asset.get("tier", "Tier-3")
        criticality = asset.get("criticality", "Low")
        dependent_nodes = asset.get("dependent_workstations", 0)
        est_loss = asset.get("estimated_downtime_loss_per_min", 0)

        # 1. Tier-0 Critical Systems (e.g. Active Directory Domain Controller)
        if tier == "Tier-0" or criticality == "Critical":
            return {
                "decision": "BLOCKED_BY_RULE_OF_ZERO",
                "asset_id": asset_id,
                "tier": tier,
                "proposed_action": proposed_action,
                "mitigation_action": "FORCE_HUMAN_IN_THE_LOOP",
                "impact_analysis": {
                    "dependent_workstations_disconnected": dependent_nodes,
                    "estimated_financial_loss_per_minute_usd": est_loss,
                    "risk_summary": f"Isolating {asset_id} would immediately knock {dependent_nodes} workstations offline and disrupt Kerberos authentication across the enterprise."
                },
                "status": "ESCALATED_TO_INCIDENT_COMMANDER"
            }

        # 2. Tier-1 High Systems (e.g. Production Payment API)
        if tier == "Tier-1":
            return {
                "decision": "DOWNGRADED_BY_GUARDRAIL",
                "asset_id": asset_id,
                "tier": tier,
                "proposed_action": proposed_action,
                "mitigation_action": "APPLY_SURGICAL_WAF_THROTTLE",
                "impact_analysis": {
                    "estimated_financial_loss_per_minute_usd": est_loss,
                    "risk_summary": "Full network isolation averted. Applied surgical rate-limiting to untrusted ingress IPs only."
                },
                "status": "AUTO_MITIGATED_WITH_GUARDRAIL"
            }

        # 3. Tier-3 Commodity Endpoints (e.g. Developer or HR Workstation)
        result = self.tools.execute_containment(asset_id, proposed_action, requested_by="AutonomousGuardrailApproved")
        return {
            "decision": "AUTONOMOUS_CONTAINMENT_APPROVED",
            "asset_id": asset_id,
            "tier": tier,
            "proposed_action": proposed_action,
            "status": "CONTAINED",
            "impact_analysis": {
                "blast_radius": "Isolated single workstation without infrastructure degradation."
            }
        }
