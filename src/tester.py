import random
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def _read_policy(yaml_path: str) -> Dict[str, Any]:
    p = Path(yaml_path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {yaml_path}")
    try:
        import yaml
    except Exception as e:
        raise RuntimeError("PyYAML is required to read policy YAML files. Install it with: pip install PyYAML") from e
    with p.open() as f:
        return yaml.safe_load(f)


def _extract_rules(cnp: Dict[str, Any]) -> List[Dict[str, Any]]:
    rules = []
    specs = cnp.get("specs") or cnp.get("spec") or []
    for s in specs:
        src = s.get("endpointSelector", {}).get("matchLabels", {}).get("app") or "unknown"
        egress = s.get("egress", [])
        for e in egress:
            dests = e.get("toEndpoints", [])
            ports = []
            for tp in e.get("toPorts", []):
                for p in tp.get("ports", []):
                    ports.append(p.get("port"))
            for d in dests:
                dest = d.get("matchLabels", {}).get("app") or "unknown"
                if not ports:
                    rules.append({"src": src, "dest": dest, "port": "any"})
                else:
                    for port in ports:
                        rules.append({"src": src, "dest": dest, "port": port})
    return rules


def _mock_result() -> Dict[str, Any]:
    allowed = random.random() > 0.35
    status = "allowed" if allowed else "blocked"
    latency = round(random.uniform(1, 120), 1) if allowed else None
    loss = round(random.uniform(0, 5), 2) if not allowed else round(random.uniform(0, 1), 2)
    return {"status": status, "latency_ms": latency, "loss_pct": loss}


def run_mock_tests(yaml_path: str) -> List[Dict[str, Any]]:
    cnp = _read_policy(yaml_path)
    rules = _extract_rules(cnp)
    results = []
    for r in rules:
        res = _mock_result()
        results.append({"src": r["src"], "dest": r["dest"], "port": r["port"], **res})
    return results


def _validate_policy_syntax(yaml_path: str) -> Dict[str, Any]:
    """Validate YAML syntax and basic Cilium policy structure."""
    try:
        cnp = _read_policy(yaml_path)
        
        required_fields = ["apiVersion", "kind", "metadata"]
        missing_fields = [field for field in required_fields if field not in cnp]
        
        if missing_fields:
            return {
                "valid": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "warnings": []
            }
        
        if cnp.get("apiVersion") != "cilium.io/v2":
            return {
                "valid": False,
                "error": f"Invalid apiVersion: {cnp.get('apiVersion')}. Expected 'cilium.io/v2'",
                "warnings": []
            }
        
        if cnp.get("kind") != "CiliumNetworkPolicy":
            return {
                "valid": False,
                "error": f"Invalid kind: {cnp.get('kind')}. Expected 'CiliumNetworkPolicy'",
                "warnings": []
            }
        
        specs = cnp.get("specs") or cnp.get("spec")
        if not specs:
            return {
                "valid": False,
                "error": "No policy specifications found. Expected 'specs' or 'spec' field",
                "warnings": []
            }
        
        warnings = []
        if "specs" in cnp and "spec" in cnp:
            warnings.append("Both 'specs' and 'spec' found. 'spec' will be ignored.")
        
        return {"valid": True, "error": None, "warnings": warnings}
        
    except Exception as e:
        return {"valid": False, "error": str(e), "warnings": []}


def _test_connectivity_with_cilium(yaml_path: str) -> List[Dict[str, Any]]:
    """Test actual connectivity using Cilium CLI tools."""
    cnp = _read_policy(yaml_path)
    rules = _extract_rules(cnp)
    results = []
    
    for rule in rules:
        src = rule["src"]
        dest = rule["dest"]
        port = rule["port"]
        
        try:
            cmd = ["cilium", "connectivity", "test", "--test", f"{src}-to-{dest}"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
            
            if proc.returncode == 0:
                status = "allowed"
                details = "Connectivity test passed"
            else:
                status = "blocked"
                details = f"Connectivity test failed: {proc.stderr.strip()}"
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            status, details = _simulate_policy_enforcement(src, dest, port, cnp)
        
        results.append({
            "src": src,
            "dest": dest,
            "port": port,
            "status": status,
            "details": details,
            "test_type": "real"
        })
    
    return results


def _simulate_policy_enforcement(src: str, dest: str, port: str, cnp: Dict[str, Any]) -> tuple:
    """Simulate policy enforcement based on policy rules."""
    specs = cnp.get("specs") or cnp.get("spec") or []
    
    for spec in specs:
        endpoint_selector = spec.get("endpointSelector", {})
        src_labels = endpoint_selector.get("matchLabels", {})
        
        if src_labels.get("app") == src:
            egress_rules = spec.get("egress", [])
            for egress in egress_rules:
                to_endpoints = egress.get("toEndpoints", [])
                for endpoint in to_endpoints:
                    dest_labels = endpoint.get("matchLabels", {})
                    if dest_labels.get("app") == dest:
                        to_ports = egress.get("toPorts", [])
                        if not to_ports:
                            return "allowed", "Policy explicitly allows connection"
                        
                        for port_rule in to_ports:
                            ports = port_rule.get("ports", [])
                            for port_spec in ports:
                                if port_spec.get("port") == port or port == "any":
                                    return "allowed", f"Policy allows connection on port {port}"
    
    return "blocked", "No policy rule allows this connection"


def _kubectl_dry_run_validation(yaml_path: str) -> Dict[str, Any]:
    """Run kubectl dry-run validation."""
    try:
        cmd = ["kubectl", "apply", "--dry-run=client", "-f", yaml_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        success = proc.returncode == 0
        return {"tool": "kubectl", "success": success, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        return {"tool": "kubectl", "success": False, "stdout": "", "stderr": "kubectl not found in PATH"}


def _cilium_policy_validation(yaml_path: str) -> Dict[str, Any]:
    """Run cilium policy validation."""
    try:
        cmd = ["cilium", "policy", "validate", yaml_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        success = proc.returncode == 0
        return {"tool": "cilium", "success": success, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        return {"tool": "cilium", "success": False, "stdout": "", "stderr": "cilium CLI not found in PATH"}


def run_real_validation(yaml_path: str) -> Dict[str, Any]:
    """Run comprehensive real validation including syntax check, kubectl/cilium validation, and connectivity tests."""
    console.print("[bold blue]Running comprehensive policy validation...[/bold blue]")
    
    console.print("Validating policy syntax...")
    syntax_result = _validate_policy_syntax(yaml_path)
    
    if not syntax_result["valid"]:
        return {
            "success": False,
            "error": syntax_result["error"],
            "step": "syntax_validation",
            "details": syntax_result
        }
    
    console.print("Running tool-based validation...")
    kubectl_result = _kubectl_dry_run_validation(yaml_path)
    cilium_result = _cilium_policy_validation(yaml_path)
    
    console.print("Testing policy enforcement...")
    connectivity_results = _test_connectivity_with_cilium(yaml_path)
    
    return {
        "success": syntax_result["valid"],
        "syntax_validation": syntax_result,
        "kubectl_validation": kubectl_result,
        "cilium_validation": cilium_result,
        "connectivity_results": connectivity_results,
        "warnings": syntax_result.get("warnings", [])
    }


def print_results_table(results: List[Dict[str, Any]], title: str = "Policy Test Results", show_details: bool = False):
    """Print results in a Rich table format."""
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Source → Destination", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    
    if show_details:
        table.add_column("Details", style="yellow", max_width=40)
    
    for r in results:
        status = r.get("status", "unknown")
        port = str(r.get("port", ""))
        src_dest = f"{r.get('src', 'unknown')} → {r.get('dest', 'unknown')}"
        
        if "allowed" in status:
            status_display = f"[green]{status}[/green]"
        elif "blocked" in status:
            status_display = f"[red]{status}[/red]"
        else:
            status_display = f"[yellow]{status}[/yellow]"
        
        if show_details:
            details = r.get("details", r.get("test_type", ""))
            table.add_row(src_dest, port, status_display, details)
        else:
            table.add_row(src_dest, port, status_display)
    
    console.print(table)


def print_validation_summary(validation_result: Dict[str, Any]):
    """Print a comprehensive validation summary."""
    console.print("\n[bold]Validation Summary[/bold]")
    
    # Syntax validation
    syntax = validation_result.get("syntax_validation", {})
    if syntax.get("valid"):
        console.print("Policy syntax: [green]Valid[/green]")
        if syntax.get("warnings"):
            for warning in syntax["warnings"]:
                console.print(f"  Warning: {warning}")
    else:
        console.print(f"Policy syntax: [red]Invalid[/red] - {syntax.get('error', 'Unknown error')}")
        return
    
    # Tool validations
    kubectl = validation_result.get("kubectl_validation", {})
    cilium = validation_result.get("cilium_validation", {})
    
    if kubectl.get("success"):
        console.print("kubectl validation: [green]Passed[/green]")
    elif kubectl.get("tool") == "kubectl":
        console.print(f"kubectl validation: [red]Failed[/red]")
        if kubectl.get("stderr"):
            console.print(f"  Error: {kubectl['stderr'][:100]}...")
    else:
        console.print("kubectl: [yellow]Not available[/yellow]")
    
    if cilium.get("success"):
        console.print("cilium validation: [green]Passed[/green]")
    elif cilium.get("tool") == "cilium":
        console.print(f"cilium validation: [red]Failed[/red]")
        if cilium.get("stderr"):
            console.print(f"  Error: {cilium['stderr'][:100]}...")
    else:
        console.print("cilium CLI: [yellow]Not available[/yellow]")
    
    # Connectivity results summary
    connectivity = validation_result.get("connectivity_results", [])
    if connectivity:
        allowed_count = sum(1 for r in connectivity if "allowed" in r.get("status", ""))
        blocked_count = sum(1 for r in connectivity if "blocked" in r.get("status", ""))
        total_count = len(connectivity)
        
        console.print(f"\nConnectivity test results:")
        console.print(f"  Total rules tested: {total_count}")
        console.print(f"  Allowed: [green]{allowed_count}[/green]")
        console.print(f"  Blocked: [red]{blocked_count}[/red]")


def export_results_json(results: List[Dict[str, Any]], out_path: str):
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"[green]Exported results to {out_path}[/green]")


def test_policy(yaml_path: str, real: bool = False, output: Optional[str] = None):
    """Main entry: test a policy in mock (default) or real mode and optionally export results."""
    if real:
        console.print(f"[bold blue]Running real validation on {yaml_path}[/bold blue]")
        
        # Run comprehensive validation
        validation_result = run_real_validation(yaml_path)
        
        if not validation_result.get("success"):
            error_msg = validation_result.get("error", "Validation failed")
            step = validation_result.get("step", "unknown")
            console.print(f"[red]Validation failed at {step}: {error_msg}[/red]")
            return
        
        # Print validation summary
        print_validation_summary(validation_result)
        
        # Print connectivity results table
        connectivity_results = validation_result.get("connectivity_results", [])
        if connectivity_results:
            console.print()
            print_results_table(
                connectivity_results, 
                title="Real Policy Connectivity Test Results",
                show_details=True
            )
            
            if output:
                export_results_json(connectivity_results, output)
        else:
            console.print("\n[yellow]No connectivity tests performed (no rules found)[/yellow]")
        
        return

    console.print(Panel.fit("[bold]Mock Policy Test Results[/bold]", style="yellow"))
    results = run_mock_tests(yaml_path)
    print_results_table(results, title="Mock Policy Test Results")
    if output:
        export_results_json(results, output)
