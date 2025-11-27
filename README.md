# CiliTest - Cilium Network Policy Dashboard

A comprehensive tool for converting, validating, and visualizing Cilium Network Policies with a clean web-based dashboard.

## Features

### Convert & Validate
- **JSON to YAML Conversion**: Convert firewall rules from JSON format to Cilium Network Policy YAML
- **Comprehensive Validation**: YAML syntax checking, schema validation, and style linting
- **Real-time Feedback**: Instant validation results with detailed error reporting
- **Smart Suggestions**: Get recommendations for policy improvements

### Interactive Visualization  
- **Network Topology Graph**: Interactive network diagrams showing service connections
- **Policy Analytics**: Statistical analysis of policy rules and configurations
- **Multi-format Support**: Upload YAML policies or JSON rules for analysis

### Clean Dashboard
- **Responsive Design**: Works on desktop and mobile devices
- **Professional UI**: Clean, accessible interface with proper color contrast
- **Status Indicators**: Clear visual feedback for validation status and policy health
- **Quick Actions**: Easy policy management with one-click operations

### CLI Tools
- **Command Line Interface**: Full CLI support for batch processing and automation
- **Batch Validation**: Validate multiple policy files simultaneously
- **Rich Terminal Output**: Colored output with tables and progress indicators

## Quick Start

### Prerequisites
- Python 3.8 or higher
- All dependencies from `requirements.txt`

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd CiliTest
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1  # Windows PowerShell
   # or
   source .venv/bin/activate      # Linux/Mac
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the dashboard:**
   ```bash
   streamlit run dashboard.py
   ```

5. **Access the application:**
   Open your browser and navigate to `http://localhost:8501`

## Screenshots

### Dashboard Overview
*Screenshots coming soon...*

### Convert & Validate
*Screenshots coming soon...*

### Policy Visualizer
*Screenshots coming soon...*

### Validation Results
*Screenshots coming soon...*

## Usage Guide

### Web Dashboard

#### 1. Convert & Validate
- Navigate to the "Convert & Validate" page
- Choose between sample data or custom JSON input
- Click "Convert to YAML" to generate Cilium Network Policy
- View validation results with detailed error analysis

#### 2. Policy Visualizer
- After converting or uploading a policy, access the "Policy Visualizer"
- View interactive network topology graphs
- Analyze policy statistics and service connections
- Explore policy components with detailed metrics

#### 3. File Upload
- Upload existing YAML policies for validation
- Upload JSON firewall rules for conversion
- Instant processing with visual feedback

#### 4. Policy Explorer
- Browse and analyze existing policy files
- Quick validation of policies in your project directory
- Load policies for visualization

### Navigation Features

#### Enhanced Sidebar
- **Dashboard Status**: Real-time status of loaded policies
- **Quick Actions**: One-click policy management
- **Session Control**: Clear policies or start fresh sessions

#### Status Indicators
- **Valid Policy**: Policy passes all validation checks
- **Invalid Policy**: Policy has errors that need fixing
- **No Policy Loaded**: Ready to convert or upload policies

### CLI Usage

#### Convert JSON to YAML
```bash
python -m src.converter input.json output.yaml
```

#### Validate Policy
```bash
python -m src.validator policy.yaml
```

#### Example with Sample Data
```bash
python -m src.converter sample_data/firewall_rules.json converted_policy.yaml
python -m src.validator converted_policy.yaml
```

## Project Structure

```
CiliTest/
├── dashboard.py              # Main Streamlit dashboard application
├── requirements.txt          # Python dependencies
├── README.md                # This file
├── src/                     # Core modules
│   ├── cli.py               # Command-line interface
│   ├── converter.py         # JSON to YAML conversion
│   ├── validator.py         # Policy validation engine
│   ├── tester.py            # Policy testing utilities
│   └── visualizer.py        # Visualization components
├── sample_data/             # Example data files
│   ├── firewall_rules.json  # Sample firewall rules
│   └── cilium_policy.yaml   # Sample Cilium policy
├── cilium_policies.yaml     # Generated policies
├── converted_policy.yaml    # Conversion output
├── test_pods.yaml          # Test pod configurations
└── results.json            # Test results
```

## Dashboard Features

### Modern UI Elements
- **Gradient Headers**: Eye-catching headers with professional styling
- **Interactive Cards**: Hover effects and smooth transitions
- **Status Badges**: Color-coded indicators for policy health
- **Responsive Layout**: Adapts to different screen sizes

### Enhanced Visualization
- **Network Graphs**: Interactive topology diagrams using Plotly
- **Policy Statistics**: Comprehensive analytics with charts
- **Real-time Updates**: Dynamic content updates based on user actions
- **Export Options**: Save and share your visualizations

## Validation Features

### Comprehensive Checks
1. **YAML Syntax Validation**: Ensures proper YAML formatting
2. **Schema Validation**: Validates against Cilium Network Policy schema
3. **Style Linting**: Checks YAML style and best practices
4. **Logical Validation**: Identifies potential policy conflicts

### Error Reporting
- **Line-by-line Errors**: Exact location of syntax issues
- **Schema Violations**: Detailed explanations of schema mismatches
- **Style Warnings**: Non-breaking style recommendations
- **Improvement Suggestions**: Smart recommendations for policy enhancement

## Analytics & Metrics

### Policy Statistics
- **Rule Counts**: Track ingress, egress, and endpoint rules
- **Service Mapping**: Visualize service-to-service connections
- **Port Analysis**: Monitor port usage and protocols
- **Complexity Metrics**: Assess policy complexity and maintainability

### Network Topology
- **Interactive Graphs**: Drag-and-drop network visualization
- **Service Discovery**: Automatic detection of services and connections
- **Connection Analysis**: Detailed view of allowed traffic flows
- **Visual Debugging**: Identify policy gaps and overlaps

## Advanced Features

### Session Management
- **Policy Persistence**: Maintain policy state across page navigation
- **Quick Actions**: Clear policies, start new sessions
- **Status Tracking**: Real-time feedback on policy status

### File Handling
- **Multiple Formats**: Support for JSON, YAML, and YML files
- **Batch Processing**: Handle multiple files simultaneously
- **Error Recovery**: Graceful handling of invalid files

### Integration Ready
- **API Compatible**: Easy integration with CI/CD pipelines
- **Export Options**: Save converted policies and validation reports
- **Command Line Tools**: Full CLI support for automation

## Testing

The project includes comprehensive testing capabilities:

### Dashboard Testing
1. **Start the dashboard**: `streamlit run dashboard.py`
2. **Test conversion**: Use sample data or upload your own JSON rules
3. **Validate policies**: Upload YAML files for validation
4. **Explore visualization**: View network graphs and analytics

### CLI Testing  
```bash
# Test conversion
python -m src.converter sample_data/firewall_rules.json test_output.yaml

# Test validation
python -m src.validator test_output.yaml

# View generated policy
cat test_output.yaml
```

## Example Workflow

1. **Convert Rules**: Start with JSON firewall rules
2. **Generate Policy**: Use the converter to create Cilium YAML
3. **Validate**: Check for errors and get improvement suggestions
4. **Visualize**: View network topology and analyze connections
5. **Refine**: Make adjustments based on validation feedback
6. **Deploy**: Use the validated policy in your Kubernetes cluster

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is open source and available under the MIT License.

## Support

If you encounter any issues or have questions:

1. Check the validation output for detailed error messages
2. Review the sample data for correct JSON format
3. Ensure all dependencies are properly installed
4. Check the Streamlit logs for any runtime errors

---

**Built using Streamlit, Plotly, NetworkX, and modern web technologies.**

**Convert • Validate • Visualize • Deploy**