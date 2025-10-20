# src/converter.py
import yaml, json
from rich.console import Console
from rich.table import Table
console = Console()

def convert_rules(json_path: str, output_path: str = "converted_policy.yaml"):
    """Convert firewall_rules.json into CiliumNetworkPolicy YAML."""
    try:
        with open(json_path) as f:
            rules = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading {json_path}: {e}[/red]")
        return

    cnp = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "generated-policy"},
        "specs": [],
    }

    for r in rules:
        spec = {
            "endpointSelector": {"matchLabels": {"app": r["src"]}},
            "egress": [{
                "toEndpoints": [{"matchLabels": {"app": r["dest"]}}],
                "toPorts": [{"ports": [{"port": str(r["port"]), "protocol": r["proto"].upper()}]}]
            }]
        }
        cnp["specs"].append(spec)

    with open(output_path, "w") as f:
        yaml.dump(cnp, f)

    table = Table(title="Converted Rules")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Port")
    table.add_column("Protocol")
    for r in rules:
        table.add_row(r["src"], r["dest"], str(r["port"]), r["proto"])
    console.print(table)
    console.print(f"[green]Saved YAML to {output_path}[/green]")
