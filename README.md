# tf-iam-scanner

A Go CLI tool that scans Terraform files and generates minimum IAM policies required for AWS resources.

## Features

- **Proper HCL Parsing**: Uses hashicorp/hcl/v2 for accurate Terraform file parsing
- **Comprehensive Permission Database**: Maps 135+ AWS resource types to required IAM actions
- **Multiple Output Formats**: JSON, YAML, and Terraform HCL formats
- **Least-Privilege Mode**: Generate separate statements per service with specific ARNs
- **Backend Detection**: Automatically detects Terraform state backend configuration
- **Service Grouping**: Intelligently groups and minimizes permissions using wildcards
- **Test Fixtures**: Includes sample Terraform configurations for testing

## Installation

Build the tool:
```bash
go mod download
go build -o tf-iam-scanner
```

Or install globally:
```bash
go install
```

## Usage

### Basic Usage

Scan current directory and output to stdout:
```bash
./tf-iam-scanner --path .
```

### Output to File

Save the generated policy to a file:
```bash
./tf-iam-scanner --path ./terraform --output policy.json
```

### Include State Backend Permissions

Include permissions for Terraform state backend (S3 and DynamoDB):
```bash
./tf-iam-scanner --path ./terraform --include-state-backend --output policy.json
```

### Least-Privilege Mode

Generate separate statements per service with specific ARNs:
```bash
./tf-iam-scanner --path ./terraform --least-privilege --output policy.json
```

### Output in YAML or Terraform Format

```bash
# YAML format
./tf-iam-scanner --path ./terraform --format yaml --output policy.yaml

# Terraform HCL format
./tf-iam-scanner --path ./terraform --format terraform --output policy.tf
```

## Flags

- `--path, -p`: Path to directory containing Terraform files (default: current directory)
- `--output, -o`: Output file path for the IAM policy (default: stdout)
- `--include-state-backend`: Include permissions for Terraform state backend operations
- `--least-privilege`: Generate separate statements per service with specific resource ARNs
- `--format, -f`: Output format (json, yaml, terraform) (default: json)

## Example

Create a sample Terraform file:
```bash
cat > example.tf << 'EOF'
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-data-bucket"
}
EOF
```

Given a Terraform file with:
```hcl
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-terraform-test"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
```

The tool will generate:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

