import typer
from rich.console import Console
from src.converter import convert_rules
from src import tester


app = typer.Typer(help="Cilium Policy CLI — convert, test, and visualize policies.")
console = Console()


@app.command()
def convert(json_file: str, output: str = "converted_policy.yaml"):
    """Convert JSON firewall rules into Cilium YAML."""
    convert_rules(json_file, output)


@app.command()
def test(policy: str = typer.Argument(..., help="Path to Cilium YAML policy"), real: bool = typer.Option(False, "--real", help="Run real validation (kubectl/cilium)"), output: str = typer.Option(None, "--output", help="Path to write JSON results")):
    """Test a given Cilium policy. By default runs mock tests. Use --real to run kubectl/cilium validation."""
    tester.test_policy(policy, real=real, output=output)


@app.command()
def visualize(policy: str = "sample_data/cilium_policy.yaml"):
    """Visualize policy connections (mock visualization)."""
    console.print(f"Visualizing [magenta]{policy}[/magenta]...", style="bold magenta")


if __name__ == "__main__":
    app()
