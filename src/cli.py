import typer
from rich.console import Console

app = typer.Typer(help="Cilium Policy CLI — convert, test, and visualize policies.")
console = Console()

@app.command()
def convert(input: str = "sample_data/firewall_rules.json"):
    """Convert firewall rules to Cilium Network Policy format."""
    console.print(f" Converting [cyan]{input}[/cyan] into Cilium policy...", style="bold green")

@app.command()
def test(policy: str = "sample_data/cilium_policy.yaml"):
    """Test a given Cilium policy (mock validation)."""
    console.print(f" Testing [yellow]{policy}[/yellow]...", style="bold blue")

@app.command()
def visualize(policy: str = "sample_data/cilium_policy.yaml"):
    """Visualize policy connections (mock visualization)."""
    console.print(f"Visualizing [magenta]{policy}[/magenta]...", style="bold magenta")

if __name__ == "__main__":
    app()
