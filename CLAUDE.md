# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Build
go build -o tf-iam-scanner

# Run all tests
go test -v ./...

# Run a single test
go test -v -run TestParsePlanFile

# Lint (uses golangci-lint, same as CI)
golangci-lint run --timeout=5m

# Validate permissions.json is well-formed JSON
jq empty permissions.json

# Docker build and run
docker build -t tf-iam-scanner .
docker run --rm -v $(pwd)/test-fixtures:/terraform:ro tf-iam-scanner --path /terraform

# Generate plan-based policy (two-step workflow)
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
tf-iam-scanner --plan-file plan.json --least-privilege
```

## Two Input Modes

The tool supports two input modes:

1. **`--path <dir>`** — Scans `.tf` files in a directory using HCL parsing. Follows local module sources (`./`, `../`). Good for quick scans without running Terraform.

2. **`--plan-file <json>`** — Parses a `terraform show -json` plan output. This is the recommended mode for production use because:
   - All modules are resolved by Terraform — no manual module resolution needed
   - Resources from `count`/`for_each` are fully expanded
   - The exact resource types are pulled from the provider's plan
   - Works with any Terraform configuration regardless of complexity

   The plan file mode is mutually exclusive with `--path`; if both are provided, `--plan-file` takes precedence.

## Architecture

This is a single-package Go CLI (`package main`) — everything lives at the repo root. There are no internal packages.

### Core Files

- **`main.go`** — CLI entry point using `cobra`. Defines all flags (`--path`, `--output`, `--include-state-backend` (default: `true`), `--least-privilege`, `--format`), validates them, calls the parser + policy generator, and writes output. Summary info goes to stderr, policy output goes to stdout (or `--output` file).
- **`parser.go`** — Two parsers: (1) HCL parsing via `hashicorp/hcl/v2` for `.tf` files, recursively following local module sources; (2) `parsePlanFile()` for `terraform show -json` output, which extracts resources from `resource_changes` and `planned_values` (including child modules). HCL parser uses `hclsyntax.ParseConfig` with a line-by-line fallback (`extractWithSimpleParsing`). `ParseResult` includes `Warnings` (non-fatal parse errors) and `Modules` (local module source paths). Structures: `Resource`, `BackendConfig`, `ParseResult`, `PermissionMap`, plus plan-specific JSON structs (`planFile`, `planResourceChange`, etc.).
- **`policy.go`** — IAM policy generation. Collects actions from parsed resources (full permissions for resources, read-only filtering via `isReadOnlyAction()` for data sources). Supports three output formats: JSON, YAML, Terraform HCL. Implements action grouping by service (individual actions only, never wildcarded) and least-privilege mode (separate statements per service with ARNs constructed from `resource_types` in the permissions DB via `constructARNPattern()`). Always includes `sts:GetCallerIdentity` when AWS resources are present.
- **`permissions.json`** — Embedded at build time via `//go:embed`. Maps ~ 120 AWS resource types and data sources (e.g., `aws_s3_bucket`, `data.aws_caller_identity`) to their required IAM actions and `resource_types` (used for ARN construction). This is the source of truth for permission mappings.

### Key Behaviors

- **No wildcard actions**: Actions are always listed individually — the old `>5 actions → service:*` behavior is removed.
- **`--include-state-backend` defaults to `true`**: Backend permissions are included by default. Use `--include-state-backend=false` to exclude.
- **Backend permissions respect the backend type**: S3 backends get S3 + DynamoDB permissions; non-AWS backends get none.
- **`iam:PassRole`** is included for resources that reference IAM roles (Lambda, EC2, ECS, EKS, CodeBuild, Step Functions, etc.).
- **`sts:GetCallerIdentity`** is always included when any AWS resources are detected.
- **Module support**: Local module sources (`./`, `../`) are followed recursively. Remote/registry modules are skipped (detected but not scanned).
- **Error resilience**: Individual `.tf` file parse failures are logged as warnings and skipped; parsing continues with remaining files.

### Data Flow

```
CLI flags → parseTerraformFiles(dir) → ParseResult{Resources, DataSources, Backend}
                 ↓
          generateIAMPolicy(result, ...) → formatted string (JSON/YAML/Terraform)
                 ↓
          stdout or --output file
```

### Critical Implementation Details

- **`permissions.json` is embedded via `//go:embed`** — the binary is fully self-contained. No external files needed at runtime. The Dockerfile does NOT need to copy `permissions.json`.
- **All code is in `package main`** — there are no exported APIs. The parser, policy generator, and CLI are tightly coupled.
- **ARN construction uses `resource_types` from permissions.json**: The `getResourceARNForService()` function reads `resource_types` from the permissions DB entries and constructs ARN patterns via `constructARNPattern()`. A `defaultARNForService()` fallback handles services without per-resource-type ARNs. When multiple resource types exist for a service, the service-level default ARN is used.
- **Data source permissions**: Data sources are looked up with a `data.` prefix first (e.g., `data.aws_caller_identity`). If no dedicated data source entry exists, it falls back to the resource entry and filters to read-only actions using `isReadOnlyAction()`.
- **Parser fallback**: When HCL parsing fails, the simple parser handles `resource`, `data`, `module`, and `terraform` blocks but won't extract attributes, nested blocks, or `count`/`for_each` meta-arguments.
- **Test fixtures are directories** under `test-fixtures/` — each test points `parseTerraformFiles()` at a directory path, not individual files. The parser walks all `.tf` files within.
- **The `permissions.json` validation in CI** uses `jq empty` — this is separate from the Go tests and must pass for CI to succeed.

### Adding Support for a New AWS Resource Type

1. Add an entry to `permissions.json` mapping the Terraform resource type to its IAM actions and `resource_types` (used for ARN construction in least-privilege mode)
2. If the resource's service uses a non-standard ARN format, you may need to add a mapping in `resourceTypeARNPath()` or `defaultARNForService()` in `policy.go`
3. Optionally add test fixtures exercising the new resource type

### Adding Support for a New Data Source

1. Add a `data.<type>` entry to `permissions.json` with read-only actions (e.g., `data.aws_iam_role` → `iam:GetRole`)
2. If no dedicated data source entry exists, the tool falls back to the resource entry and filters to read-only actions via `isReadOnlyAction()`

### CI

- **ci.yml** runs on push/PR to `main` and `develop`: Go 1.23 tests, build, and `golangci-lint`
- **release.yml** triggers on GitHub release creation: cross-compiles for linux/darwin/windows on amd64/arm64, uploads binaries + checksums as release assets
