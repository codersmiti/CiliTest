# src/converter.py
import yaml, json
from collections import defaultdict
from rich.console import Console
from rich.table import Table

console = Console()

def convert_rules(json_path: str, output_path: str = "converted_policy.yaml"):
    """Convert firewall_rules.json into grouped CiliumNetworkPolicy YAML."""
    try:
        with open(json_path) as f:
            rules = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading {json_path}: {e}[/red]")
        return

    grouped = defaultdict(list)
    for r in rules:
        grouped[r["src"]].append(r)

    cnp = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "generated-policy"},
        "specs": []
    }

    for src, entries in grouped.items():
        egress_rules = []
        for e in entries:
            egress_rules.append({
                "toEndpoints": [{"matchLabels": {"app": e["dest"]}}],
                "toPorts": [{
                    "ports": [{"port": str(e["port"]), "protocol": e["proto"].upper()}]
                }]
            })
        cnp["specs"].append({
            "endpointSelector": {"matchLabels": {"app": src}},
            "egress": egress_rules
        })

    with open(output_path, "w") as f:
        yaml.dump(cnp, f)

    table = Table(title="Converted Firewall Rules")
    table.add_column("Source")
    table.add_column("Dest")
    table.add_column("Port")
    table.add_column("Proto")
    for r in rules:
        table.add_row(r["src"], r["dest"], str(r["port"]), r["proto"].upper())
    console.print(table)
    console.print(f"[cyan]Saved YAML to {output_path}[/cyan]")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python -m src.converter <input.json> <output.yaml>")
    else:
        convert_rules(sys.argv[1], sys.argv[2])
