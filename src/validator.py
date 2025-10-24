# src/validator.py
import yaml
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from yamllint import config, linter
from jsonschema import validate, ValidationError, Draft7Validator
import io

console = Console()

# Cilium Network Policy JSON Schema
CILIUM_NETWORK_POLICY_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "CiliumNetworkPolicy",
    "type": "object",
    "required": ["apiVersion", "kind", "metadata"],
    "properties": {
        "apiVersion": {
            "type": "string",
            "enum": ["cilium.io/v2"]
        },
        "kind": {
            "type": "string",
            "enum": ["CiliumNetworkPolicy"]
        },
        "metadata": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "pattern": "^[a-z0-9]([a-z0-9\\-]*[a-z0-9])?$"
                },
                "namespace": {
                    "type": "string"
                },
                "labels": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                },
                "annotations": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                }
            },
            "additionalProperties": True
        },
        "spec": {
            "$ref": "#/definitions/CiliumNetworkPolicySpec"
        },
        "specs": {
            "type": "array",
            "items": {"$ref": "#/definitions/CiliumNetworkPolicySpec"}
        }
    },
    "oneOf": [
        {"required": ["spec"]},
        {"required": ["specs"]}
    ],
    "definitions": {
        "CiliumNetworkPolicySpec": {
            "type": "object",
            "properties": {
                "endpointSelector": {
                    "$ref": "#/definitions/LabelSelector"
                },
                "nodeSelector": {
                    "$ref": "#/definitions/LabelSelector"
                },
                "ingress": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/IngressRule"}
                },
                "egress": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/EgressRule"}
                },
                "ingressDeny": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/IngressDenyRule"}
                },
                "egressDeny": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/EgressDenyRule"}
                }
            },
            "additionalProperties": False
        },
        "LabelSelector": {
            "type": "object",
            "properties": {
                "matchLabels": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                },
                "matchExpressions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["key", "operator"],
                        "properties": {
                            "key": {"type": "string"},
                            "operator": {
                                "type": "string",
                                "enum": ["In", "NotIn", "Exists", "DoesNotExist"]
                            },
                            "values": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "additionalProperties": False
        },
        "IngressRule": {
            "type": "object",
            "properties": {
                "fromEndpoints": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/LabelSelector"}
                },
                "fromRequires": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/LabelSelector"}
                },
                "fromCIDR": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "fromCIDRSet": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["cidr"],
                        "properties": {
                            "cidr": {"type": "string"},
                            "except": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                },
                "fromEntities": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "toPorts": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/PortRule"}
                }
            },
            "additionalProperties": False
        },
        "EgressRule": {
            "type": "object",
            "properties": {
                "toEndpoints": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/LabelSelector"}
                },
                "toRequires": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/LabelSelector"}
                },
                "toCIDR": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "toCIDRSet": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["cidr"],
                        "properties": {
                            "cidr": {"type": "string"},
                            "except": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                },
                "toEntities": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "toServices": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "k8sService": {
                                "type": "object",
                                "properties": {
                                    "serviceName": {"type": "string"},
                                    "namespace": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "toPorts": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/PortRule"}
                },
                "toFQDNs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "matchName": {"type": "string"},
                            "matchPattern": {"type": "string"}
                        }
                    }
                }
            },
            "additionalProperties": False
        },
        "IngressDenyRule": {
            "type": "object",
            "properties": {
                "fromEndpoints": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/LabelSelector"}
                },
                "fromCIDR": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "fromEntities": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "toPorts": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/PortRule"}
                }
            },
            "additionalProperties": False
        },
        "EgressDenyRule": {
            "type": "object",
            "properties": {
                "toEndpoints": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/LabelSelector"}
                },
                "toCIDR": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "toEntities": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "toPorts": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/PortRule"}
                }
            },
            "additionalProperties": False
        },
        "PortRule": {
            "type": "object",
            "properties": {
                "ports": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["port", "protocol"],
                        "properties": {
                            "port": {
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "integer", "minimum": 1, "maximum": 65535}
                                ]
                            },
                            "protocol": {
                                "type": "string",
                                "enum": ["TCP", "UDP", "SCTP", "ICMP", "ICMPv6", "ANY"]
                            },
                            "endPort": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 65535
                            }
                        }
                    }
                },
                "rules": {
                    "type": "object",
                    "properties": {
                        "http": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "method": {"type": "string"},
                                    "path": {"type": "string"},
                                    "host": {"type": "string"},
                                    "headers": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    }
                                }
                            }
                        },
                        "kafka": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "apiKey": {"type": "string"},
                                    "apiVersion": {"type": "string"},
                                    "clientID": {"type": "string"},
                                    "topic": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            },
            "additionalProperties": False
        }
    }
}

class ValidationResult:
    """Represents the result of YAML validation."""
    
    def __init__(self):
        self.is_valid = True
        self.yaml_syntax_errors: List[str] = []
        self.yaml_lint_warnings: List[Dict[str, Any]] = []
        self.schema_errors: List[str] = []
        self.suggestions: List[str] = []
    
    def add_yaml_syntax_error(self, error: str):
        self.is_valid = False
        self.yaml_syntax_errors.append(error)
    
    def add_yaml_lint_warning(self, warning: Dict[str, Any]):
        self.yaml_lint_warnings.append(warning)
    
    def add_schema_error(self, error: str):
        self.is_valid = False
        self.schema_errors.append(error)
    
    def add_suggestion(self, suggestion: str):
        self.suggestions.append(suggestion)


def validate_yaml_syntax(file_path: str) -> Tuple[bool, List[str], Optional[Dict]]:
    """Validate YAML syntax and return parsed content."""
    errors = []
    parsed_content = None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            parsed_content = yaml.safe_load(file)
        return True, errors, parsed_content
    except yaml.YAMLError as e:
        errors.append(f"YAML syntax error: {str(e)}")
        return False, errors, None
    except FileNotFoundError:
        errors.append(f"File not found: {file_path}")
        return False, errors, None
    except Exception as e:
        errors.append(f"Error reading file: {str(e)}")
        return False, errors, None


def lint_yaml_style(file_path: str) -> List[Dict[str, Any]]:
    """Run yamllint to check YAML style and formatting."""
    warnings = []
    
    try:
        # Use yamllint with relaxed default configuration
        conf = config.YamlLintConfig('extends: relaxed')
        
        with open(file_path, 'r', encoding='utf-8') as file:
            for problem in linter.run(file, conf, file_path):
                warnings.append({
                    'line': problem.line,
                    'column': problem.column,
                    'level': problem.level,
                    'message': problem.message,
                    'rule': problem.rule
                })
                
    except Exception as e:
        warnings.append({
            'line': 0,
            'column': 0,
            'level': 'error',
            'message': f"Linting failed: {str(e)}",
            'rule': 'yamllint'
        })
    
    return warnings


def validate_cilium_schema(data: Dict) -> List[str]:
    """Validate parsed YAML against Cilium Network Policy schema."""
    errors = []
    
    try:
        validator = Draft7Validator(CILIUM_NETWORK_POLICY_SCHEMA)
        validation_errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
        
        for error in validation_errors:
            path = " -> ".join(str(p) for p in error.path) if error.path else "root"
            errors.append(f"Schema validation error at '{path}': {error.message}")
            
    except Exception as e:
        errors.append(f"Schema validation failed: {str(e)}")
    
    return errors


def generate_suggestions(data: Dict, validation_result: ValidationResult) -> List[str]:
    """Generate helpful suggestions based on the policy content."""
    suggestions = []
    
    if not isinstance(data, dict):
        return suggestions
    
    # Check for common issues and suggest improvements
    if data.get('kind') == 'CiliumNetworkPolicy':
        # Check if using specs vs spec
        if 'specs' in data and 'spec' in data:
            suggestions.append("Use either 'spec' (single policy) or 'specs' (multiple policies), not both")
        
        # Check for empty rules
        specs = data.get('specs', [data.get('spec')]) if data.get('specs') or data.get('spec') else []
        for i, spec in enumerate(specs):
            if not spec:
                continue
                
            spec_name = f"spec[{i}]" if 'specs' in data else 'spec'
            
            # Check for empty ingress/egress
            if 'ingress' in spec and not spec['ingress']:
                suggestions.append(f"{spec_name}: Empty ingress rules - consider removing or adding rules")
            if 'egress' in spec and not spec['egress']:
                suggestions.append(f"{spec_name}: Empty egress rules - consider removing or adding rules")
            
            # Check for missing endpoint selector
            if 'endpointSelector' not in spec:
                suggestions.append(f"{spec_name}: Missing endpointSelector - policies should target specific endpoints")
            
            # Check for overly broad selectors
            endpoint_selector = spec.get('endpointSelector', {})
            if not endpoint_selector.get('matchLabels') and not endpoint_selector.get('matchExpressions'):
                suggestions.append(f"{spec_name}: Empty endpointSelector targets all pods - consider being more specific")
    
    return suggestions


def validate_policy(file_path: str, show_details: bool = True) -> ValidationResult:
    """
    Comprehensive validation of a Cilium Network Policy YAML file.
    
    Args:
        file_path: Path to the YAML file to validate
        show_details: Whether to show detailed output
    
    Returns:
        ValidationResult object containing all validation results
    """
    result = ValidationResult()
    
    if show_details:
        console.print(f"\n[bold cyan]Validating YAML Policy:[/bold cyan] {file_path}")
    
    # Step 1: Check if file exists
    if not Path(file_path).exists():
        result.add_yaml_syntax_error(f"File not found: {file_path}")
        return result
    
    # Step 2: Validate YAML syntax
    syntax_valid, syntax_errors, parsed_data = validate_yaml_syntax(file_path)
    for error in syntax_errors:
        result.add_yaml_syntax_error(error)
    
    if not syntax_valid:
        return result
    
    # Step 3: YAML linting (style and formatting)
    lint_warnings = lint_yaml_style(file_path)
    for warning in lint_warnings:
        result.add_yaml_lint_warning(warning)
    
    # Step 4: Schema validation (only if syntax is valid)
    if parsed_data:
        schema_errors = validate_cilium_schema(parsed_data)
        for error in schema_errors:
            result.add_schema_error(error)
        
        # Step 5: Generate suggestions
        suggestions = generate_suggestions(parsed_data, result)
        for suggestion in suggestions:
            result.add_suggestion(suggestion)
    
    return result


def print_validation_report(result: ValidationResult, file_path: str):
    """Print a detailed validation report."""
    
    # Header
    if result.is_valid:
        console.print(Panel.fit(
            f"[bold green]Validation Passed[/bold green]\n"
            f"File: [white]{file_path}[/white]",
            border_style="green"
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]Validation Failed[/bold red]\n"
            f"File: [white]{file_path}[/white]",
            border_style="red"
        ))
    
    # YAML Syntax Errors
    if result.yaml_syntax_errors:
        console.print("\n[bold red]YAML Syntax Errors:[/bold red]")
        for i, error in enumerate(result.yaml_syntax_errors, 1):
            console.print(f"  {i}. [red]{error}[/red]")
    
    # Schema Validation Errors
    if result.schema_errors:
        console.print("\n[bold red]Schema Validation Errors:[/bold red]")
        for i, error in enumerate(result.schema_errors, 1):
            console.print(f"  {i}. [red]{error}[/red]")
    
    # YAML Linting Warnings
    if result.yaml_lint_warnings:
        console.print("\n[bold yellow]YAML Style Warnings:[/bold yellow]")
        
        # Create table for warnings
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Line", width=6)
        table.add_column("Col", width=5)
        table.add_column("Level", width=8)
        table.add_column("Rule", width=15)
        table.add_column("Message")
        
        for warning in result.yaml_lint_warnings:
            level_color = "red" if warning['level'] == 'error' else "yellow"
            table.add_row(
                str(warning['line']),
                str(warning['column']),
                f"[{level_color}]{warning['level']}[/{level_color}]",
                warning['rule'],
                warning['message']
            )
        
        console.print(table)
    
    # Suggestions
    if result.suggestions:
        console.print("\n[bold blue]Suggestions for Improvement:[/bold blue]")
        for i, suggestion in enumerate(result.suggestions, 1):
            console.print(f"  {i}. [blue]{suggestion}[/blue]")
    
    # Summary
    if result.is_valid and not result.yaml_lint_warnings and not result.suggestions:
        console.print(f"\n[bold green]Perfect! No issues found.[/bold green]")
    elif result.is_valid:
        warning_count = len(result.yaml_lint_warnings)
        suggestion_count = len(result.suggestions)
        console.print(f"\n[bold green]Valid policy[/bold green] with {warning_count} warnings and {suggestion_count} suggestions")
    else:
        error_count = len(result.yaml_syntax_errors) + len(result.schema_errors)
        console.print(f"\n[bold red]{error_count} error(s) must be fixed before the policy is valid[/bold red]")


def validate_multiple_policies(file_paths: List[str]) -> Dict[str, ValidationResult]:
    """Validate multiple YAML policy files and return results."""
    results = {}
    
    console.print(f"\n[bold cyan]Validating {len(file_paths)} policy files...[/bold cyan]")
    
    for file_path in file_paths:
        results[file_path] = validate_policy(file_path, show_details=False)
    
    # Summary table
    table = Table(title="Validation Summary")
    table.add_column("File", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Errors", justify="center")
    table.add_column("Warnings", justify="center")
    table.add_column("Suggestions", justify="center")
    
    for file_path, result in results.items():
        status = "[green]Valid[/green]" if result.is_valid else "[red]Invalid[/red]"
        error_count = len(result.yaml_syntax_errors) + len(result.schema_errors)
        warning_count = len(result.yaml_lint_warnings)
        suggestion_count = len(result.suggestions)
        
        table.add_row(
            Path(file_path).name,
            status,
            str(error_count) if error_count > 0 else "[dim]0[/dim]",
            str(warning_count) if warning_count > 0 else "[dim]0[/dim]",
            str(suggestion_count) if suggestion_count > 0 else "[dim]0[/dim]"
        )
    
    console.print(table)
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m src.validator <policy.yaml>")
    else:
        result = validate_policy(sys.argv[1])
        print_validation_report(result, sys.argv[1])