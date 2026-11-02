import json
import os
from typing import Dict, Any, List

class SecurityTools:
    """Mock security and infrastructure tools used by the Agentic SOC."""

    def __init__(self, asset_graph_path: str = "data/enterprise_asset_graph.json"):
        self.asset_graph = self._load_json(asset_graph_path)
        self.containment_audit_log = []

    def _load_json(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {"assets": [], "topology_edges": []}

    def check_virustotal(self, sha256: str) -> Dict[str, Any]:
        """Mock VirusTotal query."""
        known_malicious = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "7a35b12849128409182049182049182049182049182049182049182049182049"
        ]
        if sha256 in known_malicious:
            return {"reputation": "MALICIOUS", "positives": 58, "total": 72, "threat_family": "CobaltStrike/Mimikatz"}
        return {"reputation": "CLEAN", "positives": 0, "total": 72, "threat_family": None}

    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Mock AbuseIPDB reputation query."""
        malicious_ips = ["194.26.29.112", "185.220.101.5"]
        if ip in malicious_ips:
            return {"ip": ip, "abuse_confidence_score": 98, "country": "RU", "is_tor": True}
        return {"ip": ip, "abuse_confidence_score": 0, "country": "US", "is_tor": False}

    def lookup_change_ticket(self, ticket_id: str) -> Dict[str, Any]:
        """Look up enterprise ITSM change ticket database."""
        approved_tickets = {
            "CHG-99214-PATCH-TUESDAY": {
                "status": "APPROVED",
                "assignee": "svc_sccm_patch",
                "approved_by": "CAB_SecOps",
                "description": "Deploy KB504821 patch to all engineering workstations."
            },
            "CHG-99218-EMERGENCY-DNS-FIX": {
                "status": "APPROVED",
                "assignee": "ad_admin_sarah",
                "approved_by": "Infrastructure_Director",
                "description": "Emergency DNS record sync and Kerberos key re-issuance."
            }
        }
        if ticket_id in approved_tickets:
            return {"found": True, "details": approved_tickets[ticket_id]}
        return {"found": False, "details": None}

    def get_asset_metadata(self, asset_id: str) -> Dict[str, Any]:
        """Look up asset criticality and dependencies from enterprise CMDB."""
        for asset in self.asset_graph.get("assets", []):
            if asset.get("id") == asset_id or asset.get("hostname") == asset_id:
                return asset
        return {"id": asset_id, "tier": "Tier-3", "criticality": "Low", "dependent_workstations": 0}

    def execute_containment(self, asset_id: str, action: str, requested_by: str) -> Dict[str, Any]:
        """Simulate containment action execution."""
        asset = self.get_asset_metadata(asset_id)
        entry = {
            "asset_id": asset_id,
            "action": action,
            "tier": asset.get("tier"),
            "criticality": asset.get("criticality"),
            "requested_by": requested_by,
            "status": "EXECUTED"
        }
        self.containment_audit_log.append(entry)
        return entry

    def validate_query_syntax(self, query: str, engine: str) -> Dict[str, Any]:
        """
        Validate whether a generated query conforms to engine grammar and field schemas.
        """
        engine_lower = engine.lower()
        if "kql" in engine_lower:
            # Check for illegal SQL constructs or missing pipe operators
            if "select " in query.lower() or "from " in query.lower():
                return {"valid": False, "error": "Invalid syntax: SQL 'SELECT/FROM' statements are not supported in KQL."}
            if not query.strip().startswith("Device") and not query.strip().startswith("Security"):
                return {"valid": False, "error": "Invalid schema table name."}
            return {"valid": True, "parsed_ast": "KQL_Abstract_Syntax_Tree_Valid"}

        if "spl" in engine_lower:
            if "aggregate " in query.lower() or "select " in query.lower():
                return {"valid": False, "error": "Invalid syntax: 'aggregate' command not recognized in Splunk SPL."}
            if not query.strip().startswith("index="):
                return {"valid": False, "error": "Invalid search: Query must begin with target index definition."}
            return {"valid": True, "parsed_ast": "SPL_Pipeline_Tree_Valid"}

        if "sigma" in engine_lower:
            required_keys = ["title:", "logsource:", "detection:", "condition:"]
            for k in required_keys:
                if k not in query:
                    return {"valid": False, "error": f"Invalid Sigma schema: Missing required key '{k}'"}
            return {"valid": True, "parsed_ast": "Sigma_YAML_AST_Valid"}

        return {"valid": True, "parsed_ast": "Generic_Valid"}
