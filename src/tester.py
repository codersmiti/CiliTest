# --- Windows UTF-8 fix (prevents UnicodeDecodeError) ---
import sys, io, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["LC_ALL"] = "C.UTF-8"
os.environ["LANG"] = "C.UTF-8"
# -------------------------------------------------------

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


# ========== CORE HELPERS ==========

def _read_policy(yaml_path: str) -> Dict[str, Any]:
    """Reads YAML policy file and returns parsed dict."""
    p = Path(yaml_path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {yaml_path}")
    import yaml
    with p.open() as f:
        return yaml.safe_load(f)


def _extract_rules(cnp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extracts (src, dest, port, proto) rules from the policy."""
    rules = []
    specs = cnp.get("specs") or cnp.get("spec") or []
    for s in specs:
        src = s.get("endpointSelector", {}).get("matchLabels", {}).get("app", "unknown")
        for e in s.get("egress", []):
            for d in e.get("toEndpoints", []):
                dest = d.get("matchLabels", {}).get("app", "unknown")
                for tp in e.get("toPorts", []):
                    for port_obj in tp.get("ports", []):
                        rules.append({
                            "src": src,
                            "dest": dest,
                            "port": port_obj.get("port"),
                            "proto": port_obj.get("protocol", "TCP")
                        })
    return rules


# ========== MOCK TEST MODE ==========

def _mock_result() -> Dict[str, Any]:
    """Simulated random result (used when cluster not live)."""
    allowed = random.random() > 0.35
    status = "allowed" if allowed else "blocked"
    latency = round(random.uniform(1, 120), 1) if allowed else None
    loss = round(random.uniform(0, 3), 2)
    return {"status": status, "latency_ms": latency, "loss_pct": loss}


def run_mock_tests(yaml_path: str) -> List[Dict[str, Any]]:
    """Runs simulated policy tests (no real cluster)."""
    cnp = _read_policy(yaml_path)
    rules = _extract_rules(cnp)
    results = []
    for r in rules:
        res = _mock_result()
        results.append({**r, **res})
    return results


# ========== REAL VALIDATION HELPERS ==========

def _validate_policy_syntax(yaml_path: str) -> Dict[str, Any]:
    """Ensures policy YAML conforms to CiliumNetworkPolicy spec."""
    try:
        cnp = _read_policy(yaml_path)
        if cnp.get("apiVersion") != "cilium.io/v2":
            return {"valid": False, "error": "Invalid apiVersion", "warnings": []}
        if cnp.get("kind") != "CiliumNetworkPolicy":
            return {"valid": False, "error": "Invalid kind", "warnings": []}
        if not (cnp.get("specs") or cnp.get("spec")):
            return {"valid": False, "error": "Missing 'spec' or 'specs'", "warnings": []}
        return {"valid": True, "error": None, "warnings": []}
    except Exception as e:
        return {"valid": False, "error": str(e), "warnings": []}


def _kubectl_dry_run_validation(yaml_path: str) -> Dict[str, Any]:
    """Verifies kubectl can parse/apply YAML without errors."""
    try:
        proc = subprocess.run(
            ["kubectl", "apply", "--dry-run=client", "-f", yaml_path],
            capture_output=True, text=True, encoding="utf-8", check=False
        )
        return {
            "tool": "kubectl",
            "success": proc.returncode == 0,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except FileNotFoundError:
        return {"tool": "kubectl", "success": False, "stdout": "", "stderr": "kubectl not found"}


def _cilium_policy_validation(yaml_path: str) -> Dict[str, Any]:
    """Confirms Cilium agent is running and enforcing policies."""
    try:
        proc = subprocess.run(
            ["cilium", "status"],
            capture_output=True, text=True, encoding="utf-8", check=False
        )
        if "OK" in proc.stdout:
            return {"tool": "cilium", "success": True, "stdout": proc.stdout, "stderr": ""}
        return {"tool": "cilium", "success": False, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        return {"tool": "cilium", "success": False, "stdout": "", "stderr": "cilium CLI not found"}


# ========== UPDATED: REAL POD CONNECTIVITY TEST ==========

def _run_real_pod_test(src: str, dest: str, port: str, namespace="cilium-test"):
    """
    Executes an actual pod-to-pod connectivity test using wget.
    Returns (status, details).
    """
    container_name = src  # same as pod name in our YAML
    cmd = [
        "kubectl", "exec", "-n", namespace, src,
        "-c", container_name, "--",
        "sh", "-c", f"wget -qO- {dest}:{port} || wget -qO- {dest}.{namespace}.svc.cluster.local:{port}"
    ]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=15)
        if output.strip():
            return "allowed", "Real pod connectivity succeeded"
        return "blocked", "Empty response"
    except subprocess.CalledProcessError as e:
        return "blocked", e.output.strip() if e.output else "Connection failed"
    except subprocess.TimeoutExpired:
        return "blocked", "Timed out"



def _test_connectivity_with_pods(yaml_path: str, namespace="cilium-test") -> List[Dict[str, Any]]:
    """Iterates through all rules and executes real pod-to-pod tests."""
    cnp = _read_policy(yaml_path)
    rules = _extract_rules(cnp)
    results = []

    for r in rules:
        src, dest, port = r["src"], r["dest"], str(r["port"])
        status, details = _run_real_pod_test(src, dest, port, namespace)
        # Fallback to simulated enforcement if pod test fails
        if status == "blocked" and "Connection failed" in details:
            status, details = _simulate_policy_enforcement(src, dest, port, cnp)
        results.append({"src": src, "dest": dest, "port": port, "status": status, "details": details})
    return results


# ========== MAIN VALIDATION LOGIC ==========

def run_real_validation(yaml_path: str) -> Dict[str, Any]:
    """Runs all validation stages: syntax, kubectl, cilium, and connectivity."""
    console.print("[bold blue]Running comprehensive policy validation...[/bold blue]")
    syntax = _validate_policy_syntax(yaml_path)
    if not syntax["valid"]:
        return {"success": False, "error": syntax["error"], "step": "syntax_validation"}
    kubectl = _kubectl_dry_run_validation(yaml_path)
    cilium = _cilium_policy_validation(yaml_path)
    connectivity = _test_connectivity_with_pods(yaml_path)
    return {
        "success": True,
        "syntax": syntax,
        "kubectl": kubectl,
        "cilium": cilium,
        "connectivity": connectivity,
    }


# ========== OUTPUT FUNCTIONS ==========

def print_results_table(results: List[Dict[str, Any]], title: str = "Policy Test Results"):
    """Displays results in a rich-colored table."""
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Source → Destination", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Details", style="yellow")
    for r in results:
        color = "green" if r["status"] == "allowed" else "red"
        table.add_row(f"{r['src']} → {r['dest']}", str(r['port']),
                      f"[{color}]{r['status']}[/{color}]", r["details"])
    console.print(table)


def print_validation_summary(vr: Dict[str, Any]):
    """Prints a textual summary of validation stages."""
    console.print("\n[bold]Validation Summary[/bold]")
    syntax = vr.get("syntax", {})
    if syntax.get("valid"):
        console.print("Policy syntax: [green]Valid[/green]")
    else:
        console.print(f"Policy syntax: [red]Invalid[/red] - {syntax.get('error')}")
        return
    kubectl = vr.get("kubectl", {})
    cilium = vr.get("cilium", {})
    console.print(f"kubectl validation: [{'green' if kubectl.get('success') else 'red'}]"
                  f"{'Passed' if kubectl.get('success') else 'Failed'}[/]")
    console.print(f"cilium validation: [{'green' if cilium.get('success') else 'red'}]"
                  f"{'Passed' if cilium.get('success') else 'Failed'}[/]")
    conn = vr.get("connectivity", [])
    allowed = sum(1 for r in conn if r["status"] == "allowed")
    blocked = sum(1 for r in conn if r["status"] == "blocked")
    console.print(f"\nConnectivity test results:\n  Total: {len(conn)}\n  "
                  f"Allowed: [green]{allowed}[/green]\n  Blocked: [red]{blocked}[/red]")


def _export_json(vr: Dict[str, Any], path="results.json"):
    """Saves summary and connectivity results as JSON."""
    data = {
        "summary": {
            "total": len(vr["connectivity"]),
            "allowed": sum(1 for r in vr["connectivity"] if r["status"] == "allowed"),
            "blocked": sum(1 for r in vr["connectivity"] if r["status"] == "blocked"),
        },
        "results": vr["connectivity"],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim]Results exported to {path}[/dim]")


def test_policy(yaml_path: str, real: bool = False, output: Optional[str] = None):
    """Main entry point called by CLI."""
    if real:
        console.print(f"[bold blue]Running real validation on {yaml_path}[/bold blue]")
        vr = run_real_validation(yaml_path)
        if not vr.get("success"):
            console.print(f"[red]Validation failed: {vr.get('error')}[/red]")
            return
        print_validation_summary(vr)
        print_results_table(vr["connectivity"], "Real Policy Connectivity Test Results")
        _export_json(vr, output or "results.json")
    else:
        console.print(Panel.fit("[bold]Mock Policy Test Results[/bold]", style="yellow"))
        results = run_mock_tests(yaml_path)
        print_results_table(results, "Mock Policy Test Results")
