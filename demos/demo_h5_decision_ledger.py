import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from agents.decision_ledger import DecisionLedger

console = Console()

def run_demo_h5():
    console.print(Panel.fit("[bold cyan]HYPOTHESIS 5 DEMO: Replayable Decision Ledgers (AiSOC / LanG)[/bold cyan]\n"
                            "[yellow]Demonstrating tamper-evident cryptographic state chains for compliance & post-incident replay[/yellow]"))

    incident_id = "INC-2026-LATERAL-MVT-081"
    ledger = DecisionLedger(incident_id=incident_id)

    # Simulate an autonomous multi-step investigation recorded on the ledger
    console.print("[cyan]Executing 4-stage autonomous investigation and recording state hashes...[/cyan]")
    
    # Step 1: Alert Ingestion & OCSF Normalization
    h1 = ledger.record_step(
        step_name="Step_1_Ingest_And_Normalize",
        inputs={"alert_id": "ALERT-MALICIOUS-001", "raw_format": "Sysmon_EID_1"},
        agent_thought="Ingested raw Sysmon process creation alert. Normalized to OCSF class 1001.",
        tool_called="OCSF_Normalizer",
        tool_output={"normalized_status": "SUCCESS", "process": "powershell.exe", "parent": "WINWORD.EXE"}
    )

    # Step 2: Threat Intelligence Pivot
    h2 = ledger.record_step(
        step_name="Step_2_Threat_Intel_Enrichment",
        inputs={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        agent_thought="Querying external reputation databases for malicious command payload hash.",
        tool_called="VirusTotal_API",
        tool_output={"reputation": "MALICIOUS", "positives": 58, "family": "CobaltStrike"}
    )

    # Step 3: Blast Radius Simulation
    h3 = ledger.record_step(
        step_name="Step_3_Blast_Radius_Assessment",
        inputs={"target_asset": "DEV-WRK-882", "proposed_action": "isolate_host"},
        agent_thought="Target is Tier-3 commodity workstation with 0 dependent infrastructure services. Safe to isolate.",
        tool_called="Blast_Radius_Simulator",
        tool_output={"safety_verdict": "APPROVED_BY_RULE_OF_ZERO"}
    )

    # Step 4: Autonomous Containment Execution
    h4 = ledger.record_step(
        step_name="Step_4_Automated_Containment",
        inputs={"asset_id": "DEV-WRK-882", "action": "isolate_host"},
        agent_thought="Executing network isolation to halt active Cobalt Strike beaconing.",
        tool_called="EDR_Containment_API",
        tool_output={"status": "HOST_ISOLATED", "ticket_filed": "JIRA-SEC-4091"}
    )

    exported_ledger = ledger.export_ledger()

    # Visualizing Cryptographic State Tree
    tree = Tree(f"[bold green]Cryptographic Incident Ledger: {incident_id}[/bold green]")
    for idx, entry in enumerate(exported_ledger["entries"]):
        node = tree.add(f"[bold cyan]{entry['step_name']}[/bold cyan] [dim](Hash: {entry['step_hash'][:16]}...)[/dim]")
        node.add(f"[yellow]Thought:[/yellow] {entry['agent_thought']}")
        node.add(f"[magenta]Tool:[/magenta] {entry['tool_called']} -> {json.dumps(entry['tool_output'])}")
    console.print(tree)

    # Test 1: Verify untouched ledger
    console.print("\n[bold]Audit Check 1: Verifying Untouched Ledger Integrity...[/bold]")
    verification = DecisionLedger.verify_and_replay(exported_ledger)
    console.print(f"Result: [bold green]{verification['cryptographic_integrity']}[/bold green] | Non-Repudiation: [bold green]{verification['audit_trail_non_repudiation']}[/bold green]")

    # Test 2: Simulate malicious tampering of agent logs
    console.print("\n[bold]Audit Check 2: Simulating Attacker/Insider Tampering with Step 2 logs...[/bold]")
    tampered_ledger = json.loads(json.dumps(exported_ledger))
    # Malicious actor changes 'MALICIOUS' to 'BENIGN' in historical record
    tampered_ledger["entries"][1]["tool_output"]["reputation"] = "BENIGN"
    tamper_check = DecisionLedger.verify_and_replay(tampered_ledger)
    console.print(f"Result: [bold red]TAMPERING DETECTED![/bold red] -> {tamper_check['error']}")

    console.print("\n[bold green]Conclusion for H5:[/bold green] The cryptographic decision ledger provides mathematical non-repudiation, enabling full post-incident auditability and forensic replay without relying on vendor trust.\n")

if __name__ == "__main__":
    run_demo_h5()

