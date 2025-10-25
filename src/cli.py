import typer
import subprocess
import sys
from typing import Optional, List
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.converter import convert_rules
from src import tester
from src.visualizer import visualize_policy
from src.validator import validate_policy, validate_multiple_policies, print_validation_report


app = typer.Typer(help="Cilium Policy CLI — convert, test, and visualize policies.")
console = Console()


@app.command()
def convert(
    json_file: str, 
    output: str = "converted_policy.yaml",
    validate_output: bool = typer.Option(True, "--validate/--no-validate", help="Validate generated YAML after conversion")
):
    """Convert JSON firewall rules into Cilium YAML."""
    try:
        convert_rules(json_file, output)
        console.print(f"[bold green]Conversion completed successfully![/bold green]")
        
        # Optional validation of generated YAML
        if validate_output:
            console.print(f"\n[bold cyan]Validating generated policy...[/bold cyan]")
            validation_result = validate_policy(output, show_details=False)
            if validation_result.is_valid:
                console.print(f"[green]Generated policy is valid[/green]")
            else:
                console.print(f"[yellow]Generated policy has validation issues[/yellow]")
                console.print(f"[dim]Run 'cili-test validate {output}' for detailed validation report[/dim]")
        
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
def validate(
    policies: List[str] = typer.Argument(..., help="Path(s) to Cilium YAML policy files to validate"),
    summary_only: bool = typer.Option(False, "--summary", help="Show only summary table for multiple files"),
    fix_suggestions: bool = typer.Option(True, "--suggestions/--no-suggestions", help="Show improvement suggestions")
):
    """Validate Cilium Network Policy YAML files for syntax, schema, and style."""
    
    # Expand glob patterns and validate file existence
    policy_files = []
    for policy_pattern in policies:
        if '*' in policy_pattern or '?' in policy_pattern:
            # Handle glob patterns
            from glob import glob
            matched_files = glob(policy_pattern)
            if not matched_files:
                console.print(f"[yellow]No files found matching pattern: {policy_pattern}[/yellow]")
            policy_files.extend(matched_files)
        else:
            # Handle individual files
            if Path(policy_pattern).exists():
                policy_files.append(policy_pattern)
            else:
                console.print(f"[red]Policy file not found: {policy_pattern}[/red]")
                raise typer.Exit(1)
    
    if not policy_files:
        console.print("[red]No valid policy files to validate[/red]")
        raise typer.Exit(1)
    
    try:
        if len(policy_files) == 1:
            # Single file validation with detailed report
            result = validate_policy(policy_files[0])
            print_validation_report(result, policy_files[0])
            
            if not result.is_valid:
                raise typer.Exit(1)
                
        else:
            # Multiple file validation
            if summary_only:
                results = validate_multiple_policies(policy_files)
                # Check if any validation failed
                if any(not result.is_valid for result in results.values()):
                    raise typer.Exit(1)
            else:
                # Show detailed reports for each file
                all_valid = True
                for policy_file in policy_files:
                    result = validate_policy(policy_file)
                    print_validation_report(result, policy_file)
                    if not result.is_valid:
                        all_valid = False
                    console.print("")  # Add spacing between files
                
                if not all_valid:
                    raise typer.Exit(1)
        
        console.print("[bold green]All validations passed![/bold green]")
            
    except Exception as e:
        console.print(f"[red]Error during validation: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def visualize(
    policy: str = typer.Argument("converted_policy.yaml", help="Path to Cilium YAML policy"),
    output: str = typer.Option("policy_graph.png", "--output", "-o", help="Output path for generated graph image"),
    test_results: Optional[str] = typer.Option(None, "--test-results", help="Path to test results JSON file for overlay"),
    show: bool = typer.Option(False, "--show", help="Auto-open the generated graph image"),
    validate_first: bool = typer.Option(True, "--validate/--no-validate", help="Validate policy before visualization")
):
    """Visualize policy connections and generate network graph."""
    if not Path(policy).exists():
        console.print(f"[red]Policy file not found: {policy}[/red]")
        raise typer.Exit(1)
    
    # Optional validation before visualization
    if validate_first:
        console.print("[bold cyan]Validating policy before visualization...[/bold cyan]")
        validation_result = validate_policy(policy, show_details=False)
        if not validation_result.is_valid:
            console.print("[red]Policy validation failed. Visualization may produce unexpected results.[/red]")
            console.print("[dim]Run 'cili-test validate {policy}' for detailed validation report[/dim]")
            should_continue = typer.confirm("Continue with visualization anyway?")
            if not should_continue:
                raise typer.Exit(1)
        else:
            console.print("[green]Policy validation passed[/green]")
    
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
    show_graph: bool = typer.Option(False, "--show", help="Auto-open generated graph"),
    skip_validation: bool = typer.Option(False, "--skip-validation", help="Skip YAML validation step")
):
    """Run the complete workflow: convert → validate → test → visualize."""
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
    
    # Step 2: Validate (new step)
    if not skip_validation:
        console.print("\n[bold blue]Step 2: Validating generated policy...[/bold blue]")
        try:
            validation_result = validate_policy(output_yaml, show_details=False)
            if validation_result.is_valid:
                console.print("[green]Policy validation passed[/green]")
            else:
                console.print("[yellow]Policy validation found issues[/yellow]")
                error_count = len(validation_result.yaml_syntax_errors) + len(validation_result.schema_errors)
                warning_count = len(validation_result.yaml_lint_warnings)
                console.print(f"[dim]  {error_count} errors, {warning_count} warnings[/dim]")
                
                if error_count > 0:
                    console.print("[red]Critical validation errors found. Workflow cannot continue.[/red]")
                    console.print(f"[dim]Run 'cili-test validate {output_yaml}' for detailed report[/dim]")
                    raise typer.Exit(1)
                
        except Exception as e:
            console.print(f"[red]Policy validation failed: {e}[/red]")
            raise typer.Exit(1)
    
    # Step 3: Test
    step_num = 3 if not skip_validation else 2
    console.print(f"\n[bold blue]Step {step_num}: Testing policy...[/bold blue]")
    try:
        tester.test_policy(output_yaml, real=real_test, output=test_results_file)
        console.print("[green]Policy testing completed[/green]")
    except Exception as e:
        console.print(f"[red]Policy testing failed: {e}[/red]")
        raise typer.Exit(1)
    
    # Step 4: Visualize
    step_num = 4 if not skip_validation else 3
    console.print(f"\n[bold blue]Step {step_num}: Visualizing policy...[/bold blue]")
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


@app.command()
def dashboard(
    port: int = typer.Option(8501, "--port", help="Port to run the dashboard on"),
    auto_open: bool = typer.Option(True, "--open/--no-open", help="Automatically open browser")
):
    """Launch the interactive web dashboard for policy visualization."""
    dashboard_path = Path("dashboard.py")
    
    if not dashboard_path.exists():
        console.print("[red]Dashboard file not found: dashboard.py[/red]")
        console.print("[dim]Make sure you're in the correct directory[/dim]")
        raise typer.Exit(1)
    
    console.print(Panel.fit(
        f"[bold cyan]Starting Cilium Policy Dashboard[/bold cyan]\n"
        f"Port: [white]{port}[/white]\n"
        f"URL: [white]http://localhost:{port}[/white]\n"
        f"Auto-open: [white]{'Yes' if auto_open else 'No'}[/white]",
        border_style="cyan"
    ))
    
    console.print("[dim]Press Ctrl+C to stop the dashboard[/dim]")
    
    try:
        # Build streamlit command
        cmd = [
            sys.executable, "-m", "streamlit", "run", 
            str(dashboard_path),
            f"--server.port={port}",
            "--browser.gatherUsageStats=false"
        ]
        
        if not auto_open:
            cmd.append("--server.headless=true")
        
        # Launch Streamlit
        subprocess.run(cmd)
        
    except KeyboardInterrupt:
        console.print("\n[green]Dashboard stopped[/green]")
    except FileNotFoundError:
        console.print("[red]Streamlit not found. Please install it:[/red]")
        console.print("[dim]pip install streamlit[/dim]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error starting dashboard: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
