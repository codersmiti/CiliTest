import streamlit as st
import yaml
import json
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
from pathlib import Path
import tempfile

from src.converter import convert_rules
from src.validator import validate_policy, ValidationResult

# Page configuration
st.set_page_config(
    page_title="CiliTest Dashboard",
    page_icon="�️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main .block-container {
        padding-top: 1.5rem;
        max-width: 1200px;
    }
    
    .main-header {
        background: #2c3e50;
        color: #ffffff;
        padding: 1.5rem 2rem;
        border-radius: 8px;
        margin-bottom: 2rem;
        border: 1px solid #34495e;
    }
    
    .main-header h1 {
        margin: 0;
        font-size: 2rem;
        font-weight: 600;
        color: #ffffff;
    }
    
    .main-header p {
        margin: 0.5rem 0 0 0;
        color: #bdc3c7;
        font-size: 1rem;
    }
    
    .metric-card {
        background: #ffffff;
        padding: 1rem;
        border-radius: 6px;
        margin: 0.5rem 0;
        border: 1px solid #e1e8ed;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .success-metric {
        background: #ffffff;
        border-left: 4px solid #27ae60;
        color: #2c3e50;
    }

    .warning-metric {
        background: #ffffff;
        border-left: 4px solid #f39c12;
        color: #2c3e50;
    }

    .error-metric {
        background: #ffffff;
        border-left: 4px solid #e74c3c;
        color: #2c3e50;
    }

    .info-metric {
        background: #ffffff;
        border-left: 4px solid #3498db;
        color: #2c3e50;
    }
    
    .stButton > button {
        background: #3498db;
        color: #ffffff;
        border: none;
        border-radius: 4px;
        padding: 0.5rem 1rem;
        font-weight: 500;
        border: 1px solid #2980b9;
    }
    
    .stButton > button:hover {
        background: #2980b9;
        border: 1px solid #1f5f8b;
    }
    
    .stFileUploader > div > div {
        border: 2px dashed #bdc3c7;
        border-radius: 6px;
        background: #f8f9fa;
        color: #2c3e50;
    }
    
    .stFileUploader > div > div:hover {
        border-color: #3498db;
        background: #ffffff;
    }
    
    .network-graph-container {
        background: #ffffff;
        border: 1px solid #e1e8ed;
        border-radius: 6px;
        padding: 1rem;
    }
    
    .network-graph-container h3 {
        color: #2c3e50;
        margin-top: 0;
    }
    
    .stats-container {
        background: #f8f9fa;
        border: 1px solid #e1e8ed;
        border-radius: 6px;
        padding: 1rem;
    }
    
    .stats-container h3 {
        color: #2c3e50;
        margin-top: 0;
    }
    
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 6px;
    }
    
    .status-success { background-color: #27ae60; }
    .status-warning { background-color: #f39c12; }
    .status-error { background-color: #e74c3c; }
    .status-info { background-color: #3498db; }
    
    .sidebar .sidebar-content {
        background: #f8f9fa;
        border-radius: 6px;
        padding: 1rem;
    }
    
    .stats-container div[style*="color: #667eea"] {
        color: #2c3e50 !important;
    }
    
    .stats-container div[style*="color: #28a745"] {
        color: #27ae60 !important;
    }
    
    .stats-container div[style*="color: #17a2b8"] {
        color: #3498db !important;
    }
    
    .metric-card strong {
        color: #2c3e50 !important;
    }
    
    .metric-card h3 {
        color: #2c3e50 !important;
    }
    
    .metric-card p {
        color: #34495e !important;
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
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_json:
        json.dump(rules_data, temp_json, indent=2)
        temp_json_path = temp_json.name
    
    try:
        convert_rules(temp_json_path, output_name)
        with open(output_name, 'r') as f:
            yaml_content = f.read()
        return yaml_content, output_name
    finally:
        Path(temp_json_path).unlink(missing_ok=True)

def create_policy_network_graph(policy_data):
    """Create an interactive network graph from policy data."""
    G = nx.DiGraph()
    if isinstance(policy_data, dict):
        specs = policy_data.get('specs', [policy_data.get('spec', {})])
        
        for spec in specs:
            if not spec:
                continue
                
            endpoint_selector = spec.get('endpointSelector', {})
            source_labels = endpoint_selector.get('matchLabels', {})
            source_app = source_labels.get('app', 'unknown')
            G.add_node(source_app, node_type='source', color='lightblue')
            egress_rules = spec.get('egress', [])
            for rule in egress_rules:
                to_endpoints = rule.get('toEndpoints', [])
                to_ports = rule.get('toPorts', [])
                
                for endpoint in to_endpoints:
                    target_labels = endpoint.get('matchLabels', {})
                    target_app = target_labels.get('app', 'unknown')
                    G.add_node(target_app, node_type='target', color='lightgreen')
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
    
    pos = nx.spring_layout(G, k=3, iterations=50)
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
        
        node_type = G.nodes[node].get('node_type', 'unknown')
        if node_type == 'source':
            node_color.append('lightblue')
        elif node_type == 'target':
            node_color.append('lightgreen')
        else:
            node_color.append('lightgray')
        
        connections = len(list(G.neighbors(node))) + len(list(G.predecessors(node)))
        node_size.append(max(20, connections * 10))
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
            st.markdown("""
            <div class="metric-card success-metric">
                <div style="display: flex; align-items: center;">
                    <span class="status-indicator status-success"></span>
                    <strong>Valid Policy</strong>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="metric-card error-metric">
                <div style="display: flex; align-items: center;">
                    <span class="status-indicator status-error"></span>
                    <strong>Invalid Policy</strong>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        error_count = len(result.yaml_syntax_errors) + len(result.schema_errors)
        st.markdown(f"""
        <div class="metric-card {'error-metric' if error_count > 0 else 'success-metric'}">
            <div style="text-align: center;">
                <h3 style="margin: 0;">{error_count}</h3>
                <p style="margin: 0; font-weight: 600;">Errors</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        warning_count = len(result.yaml_lint_warnings)
        st.markdown(f"""
        <div class="metric-card {'warning-metric' if warning_count > 0 else 'success-metric'}">
            <div style="text-align: center;">
                <h3 style="margin: 0;">{warning_count}</h3>
                <p style="margin: 0; font-weight: 600;">Warnings</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        suggestion_count = len(result.suggestions)
        st.markdown(f"""
        <div class="metric-card {'info-metric' if suggestion_count > 0 else 'success-metric'}">
            <div style="text-align: center;">
                <h3 style="margin: 0;">{suggestion_count}</h3>
                <p style="margin: 0; font-weight: 600;">Suggestions</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
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
            st.dataframe(warnings_df, width='stretch')
    
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
    st.markdown("""
    <div class="main-header">
        <h1>Cilium Network Policy Dashboard</h1>
        <p>Convert, validate, and visualize Cilium Network Policies</p>
    </div>
    """, unsafe_allow_html=True)
    
    has_policy = 'current_policy' in st.session_state and st.session_state['current_policy']
    
    with st.sidebar:
        st.markdown("### Navigation")
        
        page_options = ["Convert & Validate", "File Upload", "Policy Explorer"]
        if has_policy:
            page_options.insert(1, "Policy Visualizer")
        
        page = st.selectbox("Choose a page", page_options)
        
        st.markdown("---")
        
        st.markdown("### Status")
        if has_policy:
            st.markdown("""
            <div style="background: #ffffff; padding: 1rem; border-radius: 6px; 
                        border-left: 4px solid #27ae60; color: #2c3e50;">
                <strong>Policy Loaded</strong><br>
                <small>Ready for visualization and analysis</small>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background: #ffffff; padding: 1rem; border-radius: 6px; 
                        border-left: 4px solid #3498db; color: #2c3e50;">
                <strong>No Policy Loaded</strong><br>
                <small>Convert or upload a policy to enable visualization</small>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("### Quick Actions")
        if st.button("Start New Session", width='stretch'):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
        
        if has_policy:
            if st.button("Clear Policy", width='stretch'):
                if 'current_policy' in st.session_state:
                    del st.session_state['current_policy']
                if 'policy_file' in st.session_state:
                    del st.session_state['policy_file']
                st.rerun()
    
    if page == "Convert & Validate":
        st.header("Convert JSON to Cilium Policy")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.subheader("Input: JSON Firewall Rules")
            
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
            
            if 'current_policy' in st.session_state and st.session_state['current_policy']:
                st.code(st.session_state['current_policy'], language='yaml')
                
                st.subheader("Validation Results")
                if 'policy_file' in st.session_state:
                    validation_result = validate_policy(st.session_state['policy_file'], show_details=False)
                    display_validation_results(validation_result)
                
                if st.button("Convert New JSON", type="secondary"):
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
                            
                            st.session_state['current_policy'] = yaml_content
                            st.session_state['policy_file'] = yaml_file
                            
                            st.success("Policy converted successfully! The output will appear above.")
                            st.rerun()
                            
                        except Exception as e:
                            st.error(f"Conversion failed: {e}")
                            if 'current_policy' in st.session_state:
                                del st.session_state['current_policy']
                            if 'policy_file' in st.session_state:
                                del st.session_state['policy_file']
                    else:
                        st.warning("Please provide valid JSON data to convert.")
    
    elif page == "Policy Visualizer":
        st.header("Policy Network Visualization")
        
        if 'current_policy' in st.session_state and st.session_state['current_policy']:
            try:
                with st.spinner("Loading policy data..."):
                    policy_data = yaml.safe_load(st.session_state['current_policy'])
                
                if not policy_data:
                    st.error("Policy data is empty or invalid")
                    return
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown("""
                    <div class="network-graph-container">
                        <h3>Network Topology</h3>
                    """, unsafe_allow_html=True)
                    
                    try:
                        G = create_policy_network_graph(policy_data)
                        if len(G.nodes()) == 0:
                            st.markdown("""
                            <div style="text-align: center; padding: 2rem; color: #2c3e50;">
                                <h4>No Network Connections Found</h4>
                                <p>This policy may not contain egress or ingress rules with endpoint connections</p>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            fig = plot_network_graph_plotly(G)
                            st.plotly_chart(fig, width='stretch')
                            
                            st.markdown(f"""
                            <div style="background: #f8f9fa; padding: 1rem; border-radius: 6px; 
                                        margin-top: 1rem; color: #2c3e50; border: 1px solid #e1e8ed;">
                                <strong>Network Statistics:</strong><br>
                                Nodes: {len(G.nodes())} | Connections: {len(G.edges())}
                            </div>
                            """, unsafe_allow_html=True)
                            
                    except Exception as graph_error:
                        st.markdown(f"""
                        <div style="background: #ffffff; padding: 1rem; border-radius: 6px; 
                                    border-left: 4px solid #e74c3c; color: #2c3e50;">
                            <strong>Visualization Error</strong><br>
                            {graph_error}<br>
                            <small>The policy structure may not be suitable for network visualization</small>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("</div>", unsafe_allow_html=True)
                
                with col2:
                    st.markdown("""
                    <div class="stats-container">
                        <h3>Policy Analytics</h3>
                    """, unsafe_allow_html=True)
                    
                    try:
                        stats_fig = create_policy_stats_chart(policy_data)
                        if stats_fig:
                            st.plotly_chart(stats_fig, width='stretch')
                        else:
                            st.markdown("""
                            <div style="text-align: center; padding: 1rem; color: #2c3e50;">
                                <p>No statistics available for this policy</p>
                            </div>
                            """, unsafe_allow_html=True)
                    except Exception as stats_error:
                        st.markdown(f"""
                        <div style="background: #ffffff; padding: 1rem; border-radius: 6px; 
                                    margin-bottom: 1rem; border-left: 4px solid #e74c3c; color: #2c3e50;">
                            <strong>Statistics Error:</strong> {stats_error}
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("<br><h4>Policy Summary</h4>", unsafe_allow_html=True)
                    
                    try:
                        specs = policy_data.get('specs', [policy_data.get('spec', {})])
                        valid_specs = [s for s in specs if s]
                        
                        summary_html = f"""
                        <div style="background: white; padding: 1rem; border-radius: 6px; 
                                    margin: 0.5rem 0; border: 1px solid #e1e8ed; color: #2c3e50;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span>Policy Specs</span>
                                <strong>{len(valid_specs)}</strong>
                            </div>
                        </div>
                        """
                        
                        if 'G' in locals() and G:
                            summary_html += f"""
                            <div style="background: white; padding: 1rem; border-radius: 6px; 
                                        margin: 0.5rem 0; border: 1px solid #e1e8ed; color: #2c3e50;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span>Total Services</span>
                                    <strong>{len(G.nodes())}</strong>
                                </div>
                            </div>
                            <div style="background: white; padding: 1rem; border-radius: 6px; 
                                        margin: 0.5rem 0; border: 1px solid #e1e8ed; color: #2c3e50;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span>Connections</span>
                                    <strong>{len(G.edges())}</strong>
                                </div>
                            </div>
                            """
                        else:
                            summary_html += """
                            <div style="background: white; padding: 1rem; border-radius: 6px; 
                                        margin: 0.5rem 0; border: 1px solid #e1e8ed; color: #2c3e50;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span>Total Services</span>
                                    <strong>0</strong>
                                </div>
                            </div>
                            <div style="background: white; padding: 1rem; border-radius: 6px; 
                                        margin: 0.5rem 0; border: 1px solid #e1e8ed; color: #2c3e50;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span>Connections</span>
                                    <strong>0</strong>
                                </div>
                            </div>
                            """
                        
                        st.markdown(summary_html, unsafe_allow_html=True)
                        
                    except Exception as summary_error:
                        st.markdown(f"""
                        <div style="background: #ffffff; padding: 1rem; border-radius: 6px; 
                                    border-left: 4px solid #e74c3c; color: #2c3e50;">
                            <strong>Summary Error:</strong> {summary_error}
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("</div>", unsafe_allow_html=True)
                
                with st.expander("View Policy YAML"):
                    st.code(st.session_state['current_policy'], language='yaml')
                
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
            st.error("No policy data available")
            st.info("Please convert or upload a policy first")
    
    elif page == "File Upload":
        st.header("Upload Policy Files")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("### Upload YAML Policy")
            st.markdown("Upload your existing Cilium Network Policy YAML file for validation and visualization.")
            uploaded_yaml = st.file_uploader("Choose a YAML file", type=['yaml', 'yml'], help="Select a .yaml or .yml file containing your Cilium Network Policy")
            
            if uploaded_yaml is not None:
                try:
                    yaml_content = uploaded_yaml.read().decode('utf-8')
                    st.code(yaml_content, language='yaml')
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_yaml:
                        temp_yaml.write(yaml_content)
                        temp_yaml_path = temp_yaml.name
                    
                    if st.button("Validate Uploaded Policy"):
                        validation_result = validate_policy(temp_yaml_path, show_details=False)
                        display_validation_results(validation_result)
                    
                    st.session_state['current_policy'] = yaml_content
                    st.session_state['policy_file'] = temp_yaml_path
                    
                except Exception as e:
                    st.error(f"Error reading YAML file: {e}")
        
        with col2:
            st.markdown("### Upload JSON Rules")
            st.markdown("Upload firewall rules in JSON format to convert them to Cilium Network Policy.")
            uploaded_json = st.file_uploader("Choose a JSON file", type=['json'], help="Select a .json file containing your firewall rules")
            
            if uploaded_json is not None:
                try:
                    json_content = uploaded_json.read().decode('utf-8')
                    json_data = json.loads(json_content)
                    st.json(json_data)
                    
                    if st.button("Convert Uploaded JSON"):
                        yaml_content, yaml_file = convert_json_to_yaml(json_data)
                        st.code(yaml_content, language='yaml')
                        
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
    
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; padding: 2rem; color: #6b7280; border-top: 1px solid #e1e8ed; margin-top: 3rem;">
        <h4 style="color: #2c3e50;">Cilium Network Policy Dashboard</h4>
        <p>Built using Streamlit, Plotly, and NetworkX</p>
        <p><small>Convert • Validate • Visualize • Deploy</small></p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.sidebar:
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center; padding: 1rem; color: #2c3e50;">
            <strong>CiliTest Dashboard</strong><br>
            <small>Built with Streamlit</small>
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()