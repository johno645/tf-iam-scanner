# tf-iam-scanner Architecture

## Overview

`tf-iam-scanner` is a Go CLI tool that analyzes Terraform configurations to generate minimum IAM policies for AWS resources.

## Components

### 1. Main Entry Point (`main.go`)
- Cobra CLI framework for argument parsing
- Command-line flags management
- Orchestrates parsing and policy generation
- Provides summary output to stderr

### 2. HCL Parser (`parser.go`)
- Uses hashicorp/hcl/v2 for proper Terraform HCL parsing
- Extracts resources, data sources, and backend configuration
- Falls back to simple string parsing if HCL parsing fails
- Loads permission database from `permissions.json`
- Walks directory recursively to find all `.tf` files

### 3. Policy Generator (`policy.go`)
- Generates IAM policies in multiple formats (JSON, YAML, Terraform)
- Groups actions by AWS service
- Supports least-privilege mode with specific ARNs
- Intelligent wildcard usage for service actions
- Handles state backend permissions

### 4. Permission Database (`permissions.json`)
- JSON file containing resource type to IAM action mappings
- 40+ AWS resource types supported
- Maps each resource to required IAM permissions
- Extensible - easy to add new resource types

## Data Flow

```
CLI Arguments → Parse Terraform Files → Extract Resources
                                          ↓
                         Load Permissions DB
                                          ↓
                         Generate IAM Policy
                                          ↓
                         Format Output (JSON/YAML/Terraform)
```

## Features

### Parsing Strategy
1. Primary: HCL v2 parsing for accurate syntax parsing
2. Fallback: Simple string-based parsing for malformed files
3. Extracts: Resources, data sources, backend configuration

### Permission Mapping
- Each AWS resource type mapped to required IAM actions
- Supports read-only permissions for data sources
- State backend detection adds S3/DynamoDB permissions

### Policy Generation
- Default: Single statement with wildcarded service actions
- Least-privilege: Separate statements per service with specific ARNs
- Format options: JSON, YAML, Terraform HCL

## Extension Points

### Adding New Resource Types
1. Add mapping to `permissions.json`:
```json
{
  "aws_new_resource": {
    "actions": ["service:Action"],
    "resource_types": []
  }
}
```

### Adding New Output Formats
1. Add format constant in `policy.go`
2. Implement case in `generateIAMPolicy()`
3. Add flag to `main.go`

### Adding Backend Detection
1. Enhance `extractBackendFromState()` in `parser.go`
2. Parse actual state JSON structure
3. Extract specific bucket/table names

## Testing

Test fixtures located in `test-fixtures/`:
- `simple/`: Basic resources (S3, Lambda, IAM)
- `complex/`: VPC, EC2, RDS, CloudWatch
- `backend/`: Terraform state backend configuration

## Dependencies

- `github.com/spf13/cobra`: CLI framework
- `github.com/hashicorp/hcl/v2`: Terraform HCL parsing
- `github.com/zclconf/go-cty`: Terraform value types
- `gopkg.in/yaml.v3`: YAML output format

## Future Enhancements

1. Remote state backend detection
2. Support for Terraform modules
3. Policy optimization suggestions
4. Integration with AWS Policy Simulator API
5. Support for custom permission mappings

