import streamlit as st
import yaml
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
from pathlib import Path
import tempfile
import io
from typing import Dict, List, Any, Optional

# Import our modules
from src.converter import convert_rules
from src.validator import validate_policy, ValidationResult
from src.tester import test_policy
import src.visualizer as viz

# Page configuration
st.set_page_config(
    page_title="CiliTest Dashboard",
    page_icon="�️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    margin: 0.5rem 0;
}

.success-metric {
    background-color: #d4edda;
    border-left: 4px solid #28a745;
}

.warning-metric {
    background-color: #fff3cd;
    border-left: 4px solid #ffc107;
}

.error-metric {
    background-color: #f8d7da;
    border-left: 4px solid #dc3545;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 2rem;
}
</style>
""", unsafe_allow_html=True)

def load_sample_data():
    """Load sample firewall rules data."""
    sample_path = Path("sample_data/firewall_rules.json")
    if sample_path.exists():
        with open(sample_path, 'r') as f:
            return json.load(f)
    return []

def convert_json_to_yaml(rules_data, output_name="dashboard_policy.yaml"):
    """Convert JSON rules to YAML policy."""
    # Save JSON to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_json:
        json.dump(rules_data, temp_json, indent=2)
        temp_json_path = temp_json.name
    
    try:
        # Convert using our converter
        convert_rules(temp_json_path, output_name)
        
        # Read the generated YAML
        with open(output_name, 'r') as f:
            yaml_content = f.read()
        
        return yaml_content, output_name
    finally:
        # Clean up temp file
        Path(temp_json_path).unlink(missing_ok=True)

def create_policy_network_graph(policy_data):
    """Create an interactive network graph from policy data."""
    G = nx.DiGraph()
    
    # Extract connections from policy specs
    if isinstance(policy_data, dict):
        specs = policy_data.get('specs', [policy_data.get('spec', {})])
        
        for spec in specs:
            if not spec:
                continue
                
            # Get source endpoint
            endpoint_selector = spec.get('endpointSelector', {})
            source_labels = endpoint_selector.get('matchLabels', {})
            source_app = source_labels.get('app', 'unknown')
            
            # Add source node
            G.add_node(source_app, node_type='source', color='lightblue')
            
            # Process egress rules
            egress_rules = spec.get('egress', [])
            for rule in egress_rules:
                to_endpoints = rule.get('toEndpoints', [])
                to_ports = rule.get('toPorts', [])
                
                for endpoint in to_endpoints:
                    target_labels = endpoint.get('matchLabels', {})
                    target_app = target_labels.get('app', 'unknown')
                    
                    # Add target node
                    G.add_node(target_app, node_type='target', color='lightgreen')
                    
                    # Add edge with port information
                    port_info = []
                    for port_rule in to_ports:
                        ports = port_rule.get('ports', [])
                        for port in ports:
                            port_info.append(f"{port.get('port', 'unknown')}/{port.get('protocol', 'TCP')}")
                    
                    edge_label = ', '.join(port_info) if port_info else 'unknown'
                    G.add_edge(source_app, target_app, label=edge_label, weight=len(port_info))
    
    return G

def plot_network_graph_plotly(G):
    """Create interactive network graph using Plotly."""
    if len(G.nodes()) == 0:
        return go.Figure().add_annotation(text="No network data to display", 
                                        xref="paper", yref="paper", x=0.5, y=0.5)
    
    # Create layout
    pos = nx.spring_layout(G, k=3, iterations=50)
    
    # Extract edges
    edge_x = []
    edge_y = []
    edge_info = []
    
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_info.append(f"{edge[0]} → {edge[1]}: {G[edge[0]][edge[1]].get('label', '')}")
    
    # Create edge trace
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=2, color='#888'),
        hoverinfo='none',
        mode='lines'
    )
    
    # Extract nodes
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
        
        # Color by node type
        node_type = G.nodes[node].get('node_type', 'unknown')
        if node_type == 'source':
            node_color.append('lightblue')
        elif node_type == 'target':
            node_color.append('lightgreen')
        else:
            node_color.append('lightgray')
        
        # Size by connectivity
        connections = len(list(G.neighbors(node))) + len(list(G.predecessors(node)))
        node_size.append(max(20, connections * 10))
    
    # Create node trace
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="middle center",
        marker=dict(
            size=node_size,
            color=node_color,
            line=dict(width=2, color='black')
        )
    )
    
    # Create figure
    fig = go.Figure(data=[edge_trace, node_trace],
                   layout=go.Layout(
                       title=dict(
                           text='Cilium Network Policy Visualization',
                           font=dict(size=16)
                       ),
                       showlegend=False,
                       hovermode='closest',
                       margin=dict(b=20,l=5,r=5,t=40),
                       annotations=[ dict(
                           text="Network connections between services",
                           showarrow=False,
                           xref="paper", yref="paper",
                           x=0.005, y=-0.002,
                           xanchor="left", yanchor="bottom",
                           font=dict(color="#888", size=12)
                       )],
                       xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                       yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                   ))
    
    return fig

def display_validation_results(result: ValidationResult):
    """Display validation results in a user-friendly format."""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if result.is_valid:
            st.success("Valid Policy")
        else:
            st.error("Invalid Policy")
    
    with col2:
        error_count = len(result.yaml_syntax_errors) + len(result.schema_errors)
        if error_count > 0:
            st.metric("Errors", error_count, delta=None)
        else:
            st.metric("Errors", 0)
    
    with col3:
        warning_count = len(result.yaml_lint_warnings)
        if warning_count > 0:
            st.metric("Warnings", warning_count)
        else:
            st.metric("Warnings", 0)
    
    with col4:
        suggestion_count = len(result.suggestions)
        if suggestion_count > 0:
            st.metric("Suggestions", suggestion_count)
        else:
            st.metric("Suggestions", 0)
    
    # Show detailed errors if any
    if result.yaml_syntax_errors or result.schema_errors:
        st.subheader("Validation Errors")
        all_errors = result.yaml_syntax_errors + result.schema_errors
        for i, error in enumerate(all_errors, 1):
            st.error(f"{i}. {error}")
    
    # Show warnings if any
    if result.yaml_lint_warnings:
        st.subheader("Style Warnings")
        warnings_df = pd.DataFrame(result.yaml_lint_warnings)
        if not warnings_df.empty:
            st.dataframe(warnings_df, use_container_width=True)
    
    # Show suggestions if any
    if result.suggestions:
        st.subheader("Suggestions for Improvement")
        for i, suggestion in enumerate(result.suggestions, 1):
            st.info(f"{i}. {suggestion}")

def create_policy_stats_chart(policy_data):
    """Create statistics charts for the policy."""
    if not isinstance(policy_data, dict):
        return None
    
    specs = policy_data.get('specs', [policy_data.get('spec', {})])
    
    # Count different rule types
    ingress_count = 0
    egress_count = 0
    endpoints_count = 0
    
    for spec in specs:
        if not spec:
            continue
        ingress_count += len(spec.get('ingress', []))
        egress_count += len(spec.get('egress', []))
        if spec.get('endpointSelector'):
            endpoints_count += 1
    
    # Create bar chart
    fig = go.Figure(data=[
        go.Bar(name='Policy Components', 
               x=['Ingress Rules', 'Egress Rules', 'Endpoint Selectors'],
               y=[ingress_count, egress_count, endpoints_count],
               marker_color=['lightcoral', 'lightskyblue', 'lightgreen'])
    ])
    
    fig.update_layout(
        title='Policy Configuration Summary',
        yaxis_title='Count',
        showlegend=False
    )
    
    return fig

def main():
    st.title("Cilium Network Policy Dashboard")
    st.markdown("Convert, validate, and visualize Cilium Network Policies")
    
    # Check if we have policy data for conditional navigation
    has_policy = 'current_policy' in st.session_state and st.session_state['current_policy']
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    
    # Build page options based on available data
    page_options = ["Convert & Validate", "File Upload", "Policy Explorer"]
    if has_policy:
        page_options.insert(1, "Policy Visualizer")
    
    page = st.sidebar.selectbox("Choose a page", page_options)
    
    # Show status in sidebar
    if has_policy:
        st.sidebar.success("Policy loaded and ready for visualization")
    else:
        st.sidebar.info("Convert or upload a policy to enable visualization")
    
    if page == "Convert & Validate":
        st.header("Convert JSON to Cilium Policy")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.subheader("Input: JSON Firewall Rules")
            
            # Option to use sample data or custom input
            input_type = st.radio("Input Type", ["Sample Data", "Custom JSON"])
            
            if input_type == "Sample Data":
                sample_data = load_sample_data()
                if sample_data:
                    st.json(sample_data)
                    json_data = sample_data
                else:
                    st.warning("No sample data found. Please use custom JSON.")
                    json_data = []
            else:
                json_input = st.text_area(
                    "Enter JSON firewall rules:",
                    value='[\n  {\n    "src": "frontend",\n    "dest": "backend",\n    "port": 80,\n    "proto": "tcp"\n  }\n]',
                    height=300
                )
                try:
                    json_data = json.loads(json_input)
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON: {e}")
                    json_data = []
        
        with col2:
            st.subheader("Output: Cilium Network Policy")
            
            # Check if we have converted content in session state
            if 'current_policy' in st.session_state and st.session_state['current_policy']:
                st.code(st.session_state['current_policy'], language='yaml')
                
                st.subheader("Validation Results")
                if 'policy_file' in st.session_state:
                    validation_result = validate_policy(st.session_state['policy_file'], show_details=False)
                    display_validation_results(validation_result)
                
                if st.button("Convert New JSON", type="secondary"):
                    # Clear existing policy to allow new conversion
                    del st.session_state['current_policy']
                    if 'policy_file' in st.session_state:
                        del st.session_state['policy_file']
                    st.rerun()
                    
            else:
                if st.button("Convert to YAML", type="primary"):
                    if json_data:
                        try:
                            with st.spinner("Converting JSON to YAML..."):
                                yaml_content, yaml_file = convert_json_to_yaml(json_data)
                            
                            # Store in session state for persistence
                            st.session_state['current_policy'] = yaml_content
                            st.session_state['policy_file'] = yaml_file
                            
                            st.success("Policy converted successfully! The output will appear above.")
                            st.rerun()  # Refresh to show the converted content
                            
                        except Exception as e:
                            st.error(f"Conversion failed: {e}")
                            # Clear any partial state
                            if 'current_policy' in st.session_state:
                                del st.session_state['current_policy']
                            if 'policy_file' in st.session_state:
                                del st.session_state['policy_file']
                    else:
                        st.warning("Please provide valid JSON data to convert.")
    
    elif page == "Policy Visualizer":
        st.header("Policy Network Visualization")
        
        # This page is only shown when we have policy data
        if 'current_policy' in st.session_state and st.session_state['current_policy']:
            try:
                with st.spinner("Loading policy data..."):
                    policy_data = yaml.safe_load(st.session_state['current_policy'])
                
                if not policy_data:
                    st.error("Policy data is empty or invalid")
                    return
                
                # Create two columns for different visualizations
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.subheader("Network Graph")
                    try:
                        G = create_policy_network_graph(policy_data)
                        if len(G.nodes()) == 0:
                            st.warning("No network connections found in this policy")
                            st.info("This policy may not contain egress or ingress rules with endpoint connections")
                        else:
                            fig = plot_network_graph_plotly(G)
                            st.plotly_chart(fig, use_container_width=True)
                    except Exception as graph_error:
                        st.error(f"Error creating network graph: {graph_error}")
                        st.info("The policy structure may not be suitable for network visualization")
                
                with col2:
                    st.subheader("Policy Statistics")
                    try:
                        stats_fig = create_policy_stats_chart(policy_data)
                        if stats_fig:
                            st.plotly_chart(stats_fig, use_container_width=True)
                        else:
                            st.info("No statistics available for this policy")
                    except Exception as stats_error:
                        st.error(f"Error creating statistics: {stats_error}")
                    
                    # Policy summary
                    st.subheader("Policy Summary")
                    try:
                        specs = policy_data.get('specs', [policy_data.get('spec', {})])
                        valid_specs = [s for s in specs if s]
                        st.metric("Policy Specs", len(valid_specs))
                        
                        if 'G' in locals() and G:
                            st.metric("Total Services", len(G.nodes()))
                            st.metric("Connections", len(G.edges()))
                        else:
                            st.metric("Total Services", 0)
                            st.metric("Connections", 0)
                    except Exception as summary_error:
                        st.error(f"Error creating summary: {summary_error}")
                
                # Display policy YAML in expandable section
                with st.expander("View Policy YAML"):
                    st.code(st.session_state['current_policy'], language='yaml')
                
                # Clear policy button
                if st.button("Clear Current Policy", type="secondary"):
                    del st.session_state['current_policy']
                    if 'policy_file' in st.session_state:
                        del st.session_state['policy_file']
                    st.rerun()
                    
            except yaml.YAMLError as yaml_error:
                st.error(f"Invalid YAML format: {yaml_error}")
                st.info("Please check your policy format and try again")
            except Exception as e:
                st.error(f"Error loading policy: {e}")
                st.info("There may be an issue with the policy data format")
        else:
            # This shouldn't happen since page is conditionally shown
            st.error("No policy data available")
            st.info("Please convert or upload a policy first")
    
    elif page == "File Upload":
        st.header("Upload Policy Files")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.subheader("Upload YAML Policy")
            uploaded_yaml = st.file_uploader("Choose a YAML file", type=['yaml', 'yml'])
            
            if uploaded_yaml is not None:
                try:
                    yaml_content = uploaded_yaml.read().decode('utf-8')
                    st.code(yaml_content, language='yaml')
                    
                    # Save to temp file for validation
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_yaml:
                        temp_yaml.write(yaml_content)
                        temp_yaml_path = temp_yaml.name
                    
                    # Validate uploaded policy
                    if st.button("Validate Uploaded Policy"):
                        validation_result = validate_policy(temp_yaml_path, show_details=False)
                        display_validation_results(validation_result)
                    
                    # Store for visualization
                    st.session_state['current_policy'] = yaml_content
                    st.session_state['policy_file'] = temp_yaml_path
                    
                except Exception as e:
                    st.error(f"Error reading YAML file: {e}")
        
        with col2:
            st.subheader("Upload JSON Rules")
            uploaded_json = st.file_uploader("Choose a JSON file", type=['json'])
            
            if uploaded_json is not None:
                try:
                    json_content = uploaded_json.read().decode('utf-8')
                    json_data = json.loads(json_content)
                    st.json(json_data)
                    
                    if st.button("Convert Uploaded JSON"):
                        yaml_content, yaml_file = convert_json_to_yaml(json_data)
                        st.code(yaml_content, language='yaml')
                        
                        # Validate converted policy
                        validation_result = validate_policy(yaml_file, show_details=False)
                        display_validation_results(validation_result)
                        
                        # Store for visualization
                        st.session_state['current_policy'] = yaml_content
                        st.session_state['policy_file'] = yaml_file
                        
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON file: {e}")
                except Exception as e:
                    st.error(f"Error processing JSON file: {e}")
    
    elif page == "Policy Explorer":
        st.header("Policy Explorer")
        
        # List available policy files
        policy_files = []
        for pattern in ["*.yaml", "*.yml"]:
            policy_files.extend(Path(".").glob(pattern))
        
        sample_policies = list(Path("sample_data").glob("*.yaml")) if Path("sample_data").exists() else []
        all_policies = policy_files + sample_policies
        
        if all_policies:
            selected_policy = st.selectbox(
                "Select a policy file to explore:",
                options=[str(p) for p in all_policies]
            )
            
            if selected_policy:
                try:
                    with open(selected_policy, 'r') as f:
                        policy_content = f.read()
                    
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.subheader("Policy Content")
                        st.code(policy_content, language='yaml')
                    
                    with col2:
                        st.subheader("Quick Validation")
                        if st.button("Validate This Policy"):
                            validation_result = validate_policy(selected_policy, show_details=False)
                            display_validation_results(validation_result)
                        
                        if st.button("Visualize This Policy"):
                            st.session_state['current_policy'] = policy_content
                            st.session_state['policy_file'] = selected_policy
                            st.success("Policy loaded! Go to 'Policy Visualizer' to see the graph.")
                    
                except Exception as e:
                    st.error(f"Error reading policy file: {e}")
        else:
            st.info("No policy files found in the current directory.")
            st.markdown("Try:")
            st.markdown("- Converting JSON rules in the 'Convert & Validate' page")
            st.markdown("- Uploading files in the 'File Upload' page")
    
    # Footer
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Cilium Policy Dashboard**")
    st.sidebar.markdown("Built with Streamlit")

if __name__ == "__main__":
    main()