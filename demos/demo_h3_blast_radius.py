import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from tools.mock_security_tools import SecurityTools
from agents.safety_guardrail_engine import SafetyGuardrailEngine

console = Console()

def run_demo_h3():
    console.print(Panel.fit("[bold cyan]HYPOTHESIS 3 DEMO: Blast-Radius Simulation & The 'Rule of Zero'[/bold cyan]\n"
                            "[yellow]Preventing catastrophic autonomous containment on Tier-0/Tier-1 enterprise infrastructure[/yellow]"))

    tools = SecurityTools()
    guardrail = SafetyGuardrailEngine(tools)

    test_scenarios = [
        {"asset_id": "DC-PRIMARY-01", "action": "isolate_host", "scenario": "Malware detected on Domain Controller"},
        {"asset_id": "PAYMENT-API-01", "action": "isolate_host", "scenario": "Brute force attack on Payment Gateway"},
        {"asset_id": "DEV-WRK-882", "action": "isolate_host", "scenario": "Cobalt Strike beacon on Dev Workstation"}
    ]

    table = Table(title="Hypothesis 3 Evaluation: Naive Auto-Containment vs. Rule-of-Zero Guardrail", show_lines=True)
    table.add_column("Asset ID", style="bold")
    table.add_column("Asset Tier", style="cyan")
    table.add_column("Naive Agent Action", style="red", width=25)
    table.add_column("Guardrail Decision & Impact Simulation", style="green", width=45)

    for item in test_scenarios:
        asset_id = item["asset_id"]
        action = item["action"]

        # Naive behavior: blindly isolates
        naive_result = f"[bold red]ISOLATED IMMEDIATELY[/bold red]\n(Caused massive operational outage)" if "DC" in asset_id or "PAYMENT" in asset_id else "[green]ISOLATED (Safe)[/green]"

        # Guardrail behavior
        guard_res = guardrail.evaluate_containment_request(asset_id, action)
        decision = guard_res["decision"]
        impact = guard_res.get("impact_analysis", {})

        if decision == "BLOCKED_BY_RULE_OF_ZERO":
            guard_str = f"[bold yellow]{decision}[/bold yellow]\n"
            guard_str += f"• Mitigation: {guard_res['mitigation_action']}\n"
            guard_str += f"• Blast Radius: {impact.get('dependent_workstations_disconnected')} workstations protected\n"
            guard_str += f"• Outage Avoided: ${impact.get('estimated_financial_loss_per_minute_usd')}/min"
        elif decision == "DOWNGRADED_BY_GUARDRAIL":
            guard_str = f"[bold cyan]{decision}[/bold cyan]\n"
            guard_str += f"• Mitigation: {guard_res['mitigation_action']}\n"
            guard_str += f"• Detail: {impact.get('risk_summary')}"
        else:
            guard_str = f"[bold green]{decision}[/bold green]\n"
            guard_str += f"• Status: {guard_res['status']} safely"

        table.add_row(asset_id, guard_res.get("tier"), naive_result, guard_str)

    console.print(table)
    console.print("\n[bold green]Conclusion for H3:[/bold green] The Rule-of-Zero Guardrail prevented full business paralysis by intercepting isolation of Tier-0 Active Directory and Tier-1 Payment systems, while safely automating containment of commodity endpoints.\n")

if __name__ == "__main__":
    run_demo_h3()

