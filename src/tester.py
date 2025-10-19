import random
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

# import yaml lazily to provide clearer error messages when PyYAML isn't installed
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
    # This function expects the converter output structure used in converter.py
    rules = []
    specs = cnp.get("specs") or cnp.get("spec") or []
    for s in specs:
        src = s.get("endpointSelector", {}).get("matchLabels", {}).get("app") or "unknown"
        # egress -> toEndpoints + toPorts
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
    status = "✅ allowed" if allowed else "❌ blocked"
    # simulate latency (ms) and packet loss (%) occasionally
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


def run_real_validation(yaml_path: str) -> Dict[str, Any]:
    # Try kubectl dry-run first; if kubectl not available, try `cilium policy validate` if present.
    # We'll run kubectl apply --dry-run=client -f <yaml>
    try:
        cmd = ["kubectl", "apply", "--dry-run=client", "-f", yaml_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        success = proc.returncode == 0
        return {"tool": "kubectl", "success": success, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        # kubectl not installed; try cilium
        try:
            cmd = ["cilium", "policy", "validate", yaml_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            success = proc.returncode == 0
            return {"tool": "cilium", "success": success, "stdout": proc.stdout, "stderr": proc.stderr}
        except FileNotFoundError as e:
            return {"tool": "none", "success": False, "stdout": "", "stderr": str(e)}


def print_results_table(results: List[Dict[str, Any]], title: str = "Mock Policy Test Results"):
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Source → Destination", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    for r in results:
        status = r.get("status")
        port = str(r.get("port"))
        src_dest = f"{r.get('src')} → {r.get('dest')}"
        table.add_row(src_dest, port, status)
    console.print(table)


def export_results_json(results: List[Dict[str, Any]], out_path: str):
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"[green]Exported results to {out_path}[/green]")


def test_policy(yaml_path: str, real: bool = False, output: Optional[str] = None):
    """Main entry: test a policy in mock (default) or real mode and optionally export results."""
    if real:
        console.print(f"[bold blue]Running real validation on {yaml_path}[/bold blue]")
        res = run_real_validation(yaml_path)
        tool = res.get("tool")
        if tool == "none":
            console.print("[red]Neither kubectl nor cilium CLI found in PATH. Cannot run real validation.[/red]")
            return
        if res.get("success"):
            console.print(Panel(f"[green]Validation successful using {tool}!\n\n{res.get('stdout')}"))
        else:
            console.print(Panel(f"[red]Validation failed using {tool}.\n\nSTDOUT:\n{res.get('stdout')}\nSTDERR:\n{res.get('stderr')}"))
        return

    # Mock mode
    console.print(Panel.fit("[bold]Mock Policy Test Results[/bold]", style="yellow"))
    results = run_mock_tests(yaml_path)
    print_results_table(results)
    if output:
        export_results_json(results, output)
