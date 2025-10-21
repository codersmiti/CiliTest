import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.converter import convert_rules
from src import tester
from src.visualizer import visualize_policy


app = typer.Typer(help="Cilium Policy CLI — convert, test, and visualize policies.")
console = Console()


@app.command()
def convert(
    json_file: str, 
    output: str = "converted_policy.yaml"
):
    """Convert JSON firewall rules into Cilium YAML."""
    try:
        convert_rules(json_file, output)
        console.print(f"[bold green]Conversion completed successfully![/bold green]")
        console.print(f"[dim]Next step: Run 'cili-test test {output}' to validate the policy[/dim]")
    except Exception as e:
        console.print(f"[red]Error during conversion: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def test(
    policy: str = typer.Argument(..., help="Path to Cilium YAML policy"), 
    real: bool = typer.Option(False, "--real", help="Run real validation (kubectl/cilium)"), 
    output: Optional[str] = typer.Option(None, "--output", help="Path to write JSON results")
):
    """Test a given Cilium policy. By default runs mock tests. Use --real to run kubectl/cilium validation."""
    try:
        tester.test_policy(policy, real=real, output=output)
        console.print(f"[bold green]Policy testing completed![/bold green]")
        
        if output:
            console.print(f"[dim]Results saved to: {output}[/dim]")
            console.print(f"[dim]Next step: Run 'cili-test visualize {policy} --test-results {output}' to visualize with test overlay[/dim]")
        else:
            console.print(f"[dim]Next step: Run 'cili-test visualize {policy}' to visualize the policy[/dim]")
    except Exception as e:
        console.print(f"[red]Error during testing: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def visualize(
    policy: str = typer.Argument("converted_policy.yaml", help="Path to Cilium YAML policy"),
    output: str = typer.Option("policy_graph.png", "--output", "-o", help="Output path for generated graph image"),
    test_results: Optional[str] = typer.Option(None, "--test-results", help="Path to test results JSON file for overlay"),
    show: bool = typer.Option(False, "--show", help="Auto-open the generated graph image")
):
    """Visualize policy connections and generate network graph."""
    if not Path(policy).exists():
        console.print(f"[red]Policy file not found: {policy}[/red]")
        raise typer.Exit(1)
    
    console.print(Panel.fit(
        f"[bold cyan]Visualizing Policy[/bold cyan]\n"
        f"Policy: [white]{policy}[/white]\n"
        f"Output: [white]{output}[/white]"
        + (f"\nTest Results: [white]{test_results}[/white]" if test_results else ""),
        border_style="blue"
    ))
    
    try:
        graph_path = visualize_policy(
            yaml_path=policy,
            output_graph=output,
            test_results=test_results,
            show_graph=show
        )
        
        console.print(f"[bold green]Visualization completed![/bold green]")
        
        if "policy_graph.png" in graph_path:
            console.print(f"[dim]Graph image created at: {graph_path}[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error during visualization: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def workflow(
    json_file: str = typer.Argument("sample_data/firewall_rules.json", help="Input JSON firewall rules"),
    output_yaml: str = typer.Option("converted_policy.yaml", "--yaml-output", help="Output YAML policy file"),
    output_graph: str = typer.Option("policy_graph.png", "--graph-output", help="Output graph image file"),
    test_results_file: str = typer.Option("test_results.json", "--test-output", help="Test results output file"),
    real_test: bool = typer.Option(False, "--real-test", help="Run real validation instead of mock tests"),
    show_graph: bool = typer.Option(False, "--show", help="Auto-open generated graph")
):
    """Run the complete workflow: convert → test → visualize."""
    console.print(Panel.fit(
        "[bold cyan]Complete Cilium Policy Workflow[/bold cyan]\n"
        f"Input: [white]{json_file}[/white] → [white]{output_yaml}[/white] → [white]{output_graph}[/white]",
        border_style="cyan"
    ))
    
    # Step 1: Convert
    console.print("\n[bold blue]Step 1: Converting firewall rules...[/bold blue]")
    try:
        convert_rules(json_file, output_yaml)
        console.print("[green]Conversion completed[/green]")
    except Exception as e:
        console.print(f"[red]Conversion failed: {e}[/red]")
        raise typer.Exit(1)
    
    # Step 2: Test
    console.print("\n[bold blue]Step 2: Testing policy...[/bold blue]")
    try:
        tester.test_policy(output_yaml, real=real_test, output=test_results_file)
        console.print("[green]Policy testing completed[/green]")
    except Exception as e:
        console.print(f"[red]Policy testing failed: {e}[/red]")
        raise typer.Exit(1)
    
    # Step 3: Visualize
    console.print("\n[bold blue]Step 3: Visualizing policy...[/bold blue]")
    try:
        graph_path = visualize_policy(
            yaml_path=output_yaml,
            output_graph=output_graph,
            test_results=test_results_file,
            show_graph=show_graph
        )
        console.print("[green]Visualization completed[/green]")
    except Exception as e:
        console.print(f"[red]Visualization failed: {e}[/red]")
        raise typer.Exit(1)
    
    # Final summary
    console.print(Panel.fit(
        "[bold green]Workflow Completed Successfully![/bold green]\n\n"
        f"Files created:\n"
        f"  Policy: [white]{output_yaml}[/white]\n"
        f"  Test Results: [white]{test_results_file}[/white]\n"
        f"  Visualization: [white]{output_graph if 'png' in output_graph else 'Console ASCII'}[/white]",
        border_style="green"
    ))


if __name__ == "__main__":
    app()
