import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import subprocess
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

console = Console()

def _check_and_install_visualization_deps():
    """Check and install visualization dependencies if needed."""
    required_packages = ['networkx', 'matplotlib']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        console.print(f"[yellow]Installing missing packages: {', '.join(missing_packages)}[/yellow]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task(description="Installing packages...", total=None)
            
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", 
                    *missing_packages
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                progress.update(task, completed=True)
                console.print("[green]Visualization packages installed successfully[/green]")
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Failed to install packages: {e}[/red]")
                return False
    
    return True


def _read_policy(yaml_path: str) -> Dict[str, Any]:
    """Read and parse YAML policy file."""
    p = Path(yaml_path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {yaml_path}")
    
    with p.open() as f:
        return yaml.safe_load(f)


def _extract_connections(cnp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract connections from Cilium Network Policy."""
    connections = []
    
    specs = []
    if "specs" in cnp and cnp["specs"]:
        specs = cnp["specs"]
    elif "spec" in cnp and cnp["spec"]:
        specs = [cnp["spec"]]
    
    for spec in specs:
        if not spec:
            continue
            
        src = spec.get("endpointSelector", {}).get("matchLabels", {}).get("app") or "unknown-source"
        egress_rules = spec.get("egress", [])
        
        for egress in egress_rules:
            dest_endpoints = egress.get("toEndpoints", [])
            port_rules = egress.get("toPorts", [])
            
            for endpoint in dest_endpoints:
                dest = endpoint.get("matchLabels", {}).get("app") or "unknown-dest"
                
                if port_rules:
                    for port_rule in port_rules:
                        ports = port_rule.get("ports", [])
                        for port_spec in ports:
                            port = port_spec.get("port", "unknown")
                            protocol = port_spec.get("protocol", "TCP")
                            connections.append({
                                "src": src,
                                "dest": dest,
                                "port": port,
                                "protocol": protocol,
                                "connection_type": "egress"
                            })
                else:
                    connections.append({
                        "src": src,
                        "dest": dest,
                        "port": "any",
                        "protocol": "any",
                        "connection_type": "egress"
                    })
    
    return connections


def _create_network_graph(connections: List[Dict[str, Any]], output_path: str = "policy_graph.png") -> str:
    """Create and save a network graph visualization."""
    if not _check_and_install_visualization_deps():
        return _create_ascii_visualization(connections)
    
    try:
        import networkx as nx
        import matplotlib.pyplot as plt
        import matplotlib.patches as patches
        from collections import defaultdict
        
        G = nx.DiGraph()
        
        edge_labels = {}
        edge_colors = []
        node_colors = []
        nodes = set()
        
        for conn in connections:
            nodes.add(conn["src"])
            nodes.add(conn["dest"])
        
        for node in nodes:
            G.add_node(node)
            if any(conn["src"] == node for conn in connections):
                if any(conn["dest"] == node for conn in connections):
                    node_colors.append('#FFD700')
                else:
                    node_colors.append('#87CEEB')
            else:
                node_colors.append('#98FB98')
        
        for conn in connections:
            src, dest = conn["src"], conn["dest"]
            port_proto = f"{conn['port']}/{conn['protocol']}"
            
            if G.has_edge(src, dest):
                existing_label = edge_labels.get((src, dest), "")
                edge_labels[(src, dest)] = f"{existing_label}, {port_proto}" if existing_label else port_proto
            else:
                G.add_edge(src, dest)
                edge_labels[(src, dest)] = port_proto
                edge_colors.append('#4169E1')
        
        plt.figure(figsize=(12, 8))
        plt.title("Cilium Network Policy Visualization", fontsize=16, fontweight='bold', pad=20)
        
        pos = nx.spring_layout(G, k=3, iterations=50, seed=42)
        
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000, alpha=0.8)
        
        nx.draw_networkx_edges(G, pos, edge_color=edge_colors, arrows=True, 
                              arrowsize=20, arrowstyle='->', alpha=0.7, width=2)
        
        nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')
        
        edge_pos = {}
        for edge, label in edge_labels.items():
            x1, y1 = pos[edge[0]]
            x2, y2 = pos[edge[1]]
            edge_pos[edge] = ((x1 + x2) / 2, (y1 + y2) / 2 + 0.05)
        
        for edge, label_pos in edge_pos.items():
            plt.annotate(edge_labels[edge], label_pos, fontsize=8, ha='center', 
                        bbox=dict(boxstyle='round,pad=0.2', facecolor='white', alpha=0.7))
        
        legend_elements = [
            patches.Patch(color='#87CEEB', label='Source Only'),
            patches.Patch(color='#98FB98', label='Destination Only'),
            patches.Patch(color='#FFD700', label='Source & Destination'),
            patches.Patch(color='#4169E1', label='Allowed Connection')
        ]
        plt.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(1, 1))
        
        plt.axis('off')
        plt.tight_layout()
        
        full_path = Path(output_path).absolute()
        plt.savefig(full_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(full_path)
        
    except Exception as e:
        console.print(f"[yellow]Failed to create graph visualization: {e}[/yellow]")
        console.print("[yellow]Falling back to ASCII visualization...[/yellow]")
        return _create_ascii_visualization(connections)


def _create_ascii_visualization(connections: List[Dict[str, Any]]) -> str:
    """Create ASCII art visualization when matplotlib is not available."""
    console.print("\n[bold cyan]Policy Network Diagram (ASCII)[/bold cyan]")
    
    src_groups = {}
    for conn in connections:
        src = conn["src"]
        if src not in src_groups:
            src_groups[src] = []
        src_groups[src].append(conn)
    
    for src, conns in src_groups.items():
        console.print(f"\n[bold blue]{src}[/bold blue]")
        for i, conn in enumerate(conns):
            is_last = i == len(conns) - 1
            prefix = "└─" if is_last else "├─"
            port_info = f"{conn['port']}/{conn['protocol']}"
            console.print(f"  {prefix}[green]→[/green] [yellow]{conn['dest']}[/yellow] ([magenta]{port_info}[/magenta])")
    
    return "ASCII visualization displayed in console"


def _display_connections_table(connections: List[Dict[str, Any]]):
    """Display connections in a Rich table format."""
    table = Table(title="Policy Connections", box=box.ROUNDED)
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("→", style="green", justify="center", width=3)
    table.add_column("Destination", style="yellow", no_wrap=True)
    table.add_column("Port", style="magenta", justify="center")
    table.add_column("Protocol", style="blue", justify="center")
    table.add_column("Type", style="white", justify="center")
    
    for conn in connections:
        table.add_row(
            conn["src"],
            "→",
            conn["dest"],
            str(conn["port"]),
            conn["protocol"],
            conn["connection_type"]
        )
    
    console.print(table)


def _load_test_results(test_results_path: Optional[str] = None) -> Dict[str, str]:
    """Load test results if available to overlay on visualization."""
    if not test_results_path or not Path(test_results_path).exists():
        return {}
    
    try:
        with open(test_results_path) as f:
            results = json.load(f)
        
        lookup = {}
        for result in results:
            key = (result.get("src"), result.get("dest"), str(result.get("port", "")))
            lookup[key] = result.get("status", "unknown")
        
        return lookup
    except Exception as e:
        console.print(f"[yellow]Could not load test results: {e}[/yellow]")
        return {}


def visualize_policy(
    yaml_path: str, 
    output_graph: str = "policy_graph.png",
    test_results: Optional[str] = None,
    show_graph: bool = False
) -> str:
    """
    Main visualization function.
    
    Args:
        yaml_path: Path to Cilium YAML policy
        output_graph: Output path for graph image
        test_results: Optional path to test results JSON file
        show_graph: Whether to attempt to open the generated graph
        
    Returns:
        Path to generated graph or description of ASCII output
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    ) as progress:
        
        task = progress.add_task(description="Parsing policy file...", total=100)
        
        try:
            cnp = _read_policy(yaml_path)
            progress.update(task, advance=25, description="Extracting connections...")
            
            connections = _extract_connections(cnp)
            
            if not connections:
                console.print("[yellow]No connections found in policy file[/yellow]")
                return "No connections to visualize"
            
            progress.update(task, advance=25, description="Loading test results...")
            
            test_lookup = _load_test_results(test_results)
            
            progress.update(task, advance=25, description="Generating visualization...")
            
            graph_path = _create_network_graph(connections, output_graph)
            
            progress.update(task, advance=25, description="Finalizing...")
            
        except Exception as e:
            console.print(f"[red]Error visualizing policy: {e}[/red]")
            return f"Error: {e}"
    
    # Display summary information
    console.print(f"\n[bold green]Policy visualization complete![/bold green]")
    
    _display_connections_table(connections)
    
    if test_lookup:
        console.print(f"\n[bold blue]Test Results Overlay:[/bold blue]")
        overlay_table = Table(box=box.SIMPLE)
        overlay_table.add_column("Connection", style="cyan")
        overlay_table.add_column("Status", style="white")
        
        for conn in connections:
            key = (conn["src"], conn["dest"], str(conn["port"]))
            status = test_lookup.get(key, "not tested")
            
            if "allowed" in status:
                status_display = f"[green]{status}[/green]"
            elif "blocked" in status:
                status_display = f"[red]{status}[/red]"
            else:
                status_display = f"[yellow]{status}[/yellow]"
            
            connection_str = f"{conn['src']} → {conn['dest']}:{conn['port']}"
            overlay_table.add_row(connection_str, status_display)
        
        console.print(overlay_table)
    
    if "policy_graph.png" in graph_path:
        console.print(f"\n[bold cyan]Graph saved to:[/bold cyan] [white]{graph_path}[/white]")
        
        if show_graph:
            try:
                import webbrowser
                webbrowser.open(f"file://{graph_path}")
                console.print("[green]Graph opened in default viewer[/green]")
            except Exception as e:
                console.print(f"[yellow]Could not auto-open graph: {e}[/yellow]")
    else:
        console.print(f"\n{graph_path}")
    
    sources = set(conn["src"] for conn in connections)
    destinations = set(conn["dest"] for conn in connections)
    
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  [cyan]{len(connections)}[/cyan] connections")
    console.print(f"  [blue]{len(sources)}[/blue] source services")
    console.print(f"  [yellow]{len(destinations)}[/yellow] destination services")
    
    return graph_path


def main():
    """CLI entry point for standalone usage."""
    import sys
    
    if len(sys.argv) < 2:
        console.print("[red]Usage: python visualizer.py <policy.yaml> [output.png][/red]")
        return
    
    yaml_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "policy_graph.png"
    
    visualize_policy(yaml_path, output_path, show_graph=True)


if __name__ == "__main__":
    main()
