# Improvement Suggestions for tf-iam-scanner

Evaluated against the goal: **generate a least-privilege IAM policy to deploy an AWS Terraform stack.**

---

## 🔴 Critical — Blocks the stated goal

### 1. Wildcard aggregation destroys least-privilege intent

The threshold of `>5` actions per service triggers `service:*` (policy.go:170). A single `aws_iam_role` resource contributes 8 IAM actions, which immediately wildcards to `iam:*` — granting full IAM access. Five resources can easily blow 3+ services to `*:*`.

**Example:** Running on `test-fixtures/simple` (only 5 resources) outputs `s3:*`, `lambda:*`, `iam:*` — granting full admin access to S3, Lambda, and IAM. This is not least-privilege; it's the opposite.

**Fix:** Remove automatic wildcarding entirely, or make it opt-in via a flag like `--allow-service-wildcard`. The default should always list individual actions. Even with 100 actions, least-privilege means listing them all.

### 2. Backend permissions added unconditionally when backend detected

policy.go:66 — the condition is `includeStateBackend || result.Backend != nil`. This means backend S3/DynamoDB permissions are always added whenever a backend is found in the Terraform config, regardless of the `--include-state-backend` flag. Meanwhile, main.go:93 tells the user to use the flag — misleading them into thinking the permissions aren't already there.

**Fix:** Change to `if includeStateBackend {` only. If a backend is detected but the flag wasn't passed, simply inform the user via the hint.

### 3. `iam:PassRole` is completely missing

This is the most critical permission for Terraform deployment. Any resource that references an IAM role (Lambda functions, EC2 instances, ECS tasks, EKS clusters, CodeBuild projects, API Gateway, Step Functions, etc.) requires `iam:PassRole` to pass that role to the service. Without it, Terraform cannot deploy those resources.

**Fix:** Add `iam:PassRole` to every resource entry that references `role_arn` or `iam_role` as a common attribute, or add it globally when any role-referencing resource is detected. At minimum, add it to: `aws_lambda_function`, `aws_instance`, `aws_ecs_service`, `aws_ecs_task_definition`, `aws_eks_cluster`, `aws_eks_node_group`, `aws_codebuild_project`, `aws_config_configuration_recorder`, `aws_sfn_state_machine`, `aws_api_gateway_rest_api`, `aws_cloudwatch_event_target`.

### 4. `permissions.json` loaded relative to `$PWD`

parser.go:51 — `os.ReadFile("permissions.json")`. If the binary is run from any directory other than the one containing `permissions.json`, it fails silently or panics. This breaks `go install` users and any automation that runs the binary from a different working directory.

**Fix:** Embed `permissions.json` with `//go:embed`, or resolve the path relative to the binary location using `os.Executable()`, or search parent directories. Embedding is the simplest and most robust.

---

## 🟠 High Impact — Substantial correctness gaps

### 5. `resource_types` field in permissions.json is never used

Every entry in `permissions.json` has a `resource_types` array (e.g., `["bucket"]`, `["instance"]`, `["vpc"]`), but it's completely ignored. The least-privilege mode uses a separate hardcoded `getResourceARNForService()` map in policy.go instead. This means:

- Two sources of truth that will drift
- ARN patterns are per-service (e.g., `arn:aws:ec2:*:*:*`) rather than per-resource-type (e.g., `arn:aws:ec2:*:*:instance/*` for instances vs `arn:aws:ec2:*:*:vpc/*` for VPCs)
- Adding a new resource type requires editing both files

**Fix:** Use `resource_types` from the permissions DB to construct ARN patterns directly. Remove the hardcoded `getResourceARNForService()` map.

### 6. Incomplete / incorrect permission mappings

Several entries have missing or wrong permissions:

| Resource | Missing Actions |
|---|---|
| `aws_secretsmanager_secret` | `PutSecretValue`, `GetSecretValue` — needed to create/read secret versions |
| `aws_kms_key` | `EnableKeyRotation`, `ScheduleKeyDeletion`, `TagResource`, `UntagResource`, `CreateAlias` |
| `aws_instance` | `StartInstances`, `StopInstances` — lifecycle management |
| `aws_lambda_function` | `PutFunctionEventInvokeConfig`, `DeleteFunctionEventInvokeConfig` |
| `aws_rds_instance` | `AddTagsToResource`, `ListTagsForResource`, `CreateDBSnapshot` |
| `aws_s3_bucket` | `PutBucketTagging`, `GetBucketTagging`, `PutBucketAcl`, `GetBucketAcl` |
| `aws_ecs_service` | `UpdateService`, `DeleteService` are present, but `DescribeTasks`, `ListTasks` are missing |
| `aws_autoscaling_group` | Missing `SetDesiredCapacity`, `TerminateInstanceInAutoScalingGroup` |
| `aws_lb` / `aws_elb` | Missing `AddTags`, `RemoveTags`, `SetSecurityGroups`, `SetSubnets` |
| `aws_cloudwatch_log_group` | Missing `PutRetentionPolicy`, `DeleteRetentionPolicy`, `TagLogGroup` |
| `aws_dynamodb_table` | Missing `UpdateContinuousBackups`, `UpdateTimeToLive`, `TagResource` |
| `aws_iam_role` | Missing `PutRolePermissionsBoundary`, `DeleteRolePermissionsBoundary` |
| `aws_apigateway_*` | Missing `apigateway:TagResource`, `apigateway:UpdateRestApi` is `PutRestApi` (wrong action name) |
| `aws_sns_topic` | Missing `TagResource`, `UntagResource` |

### 7. No STS permissions for provider initialization

The AWS Terraform provider always calls `sts:GetCallerIdentity` on initialization to validate credentials. This is missing from all generated policies. Also, `data.aws_caller_identity` and `data.aws_region` are commonly used data sources that need `sts:GetCallerIdentity`.

**Fix:** Always include `sts:GetCallerIdentity` in the generated policy, or add it when AWS resources are detected.

### 8. Data source permission filtering is naive

policy.go:54-61 filters data source actions to only those containing "Describe", "Get", or "List". This misses valid read actions like `s3:HeadBucket`, `s3:HeadObject`, `kms:Decrypt`, `secretsmanager:GetSecretValue` (contains "Get" so it would match), but the prefix check `strings.TrimPrefix(dataSource.Type, "data.")` is always a no-op because data source types from the parser never have a "data." prefix — they're the raw block label.

**Fix:** Use a proper read-only action suffix list or tag read vs write actions in `permissions.json` itself, then filter by tag rather than string matching.

---

## 🟡 Medium Impact — Architecture & robustness

### 9. No support for Terraform modules

Real Terraform stacks use modules — local (`source = "./modules/foo"`) and remote (Terraform Registry, Git). The tool only scans `.tf` files in a single directory. Most real-world Terraform defines resources inside modules, so the scanner will find nothing useful.

**Fix:** Add `terraform init` + `terraform plan` integration to extract the full resource graph, or implement module resolution (at minimum local modules with `source = "./..."`). Alternatively, support reading a `terraform plan` JSON output directly, which contains all resolved resources.

### 10. No resource-level ARN scoping

Even in least-privilege mode, ARNs use service-level wildcards (`arn:aws:s3:::*`). A true least-privilege policy should scope to specific resources. The tool has access to resource names and attributes from the HCL parse but doesn't use them.

**Fix:** Extract resource names from the HCL, construct specific ARNs using the `resource_types` field from permissions.json, and scope statements to `arn:aws:s3:::my-bucket` instead of `arn:aws:s3:::*`. For resources with `count`/`for_each`, use `*` or a partial wildcard.

### 11. No support for `data` sources referencing IAM roles

Terraform patterns like `data.aws_iam_role.existing` need `iam:GetRole` to resolve. The tool currently only looks up permissions for `data` block types in the same `permissions.json` as resources, which doesn't have entries for data source variants.

**Fix:** Add `data.aws_iam_role`, `data.aws_caller_identity`, `data.aws_region`, `data.aws_availability_zones`, `data.aws_ssm_parameter` and other common data source entries to the permissions DB.

### 12. Hardcoded backend permission list with no detection

policy.go:67-70 hardcodes S3 + DynamoDB backend permissions. But Terraform supports many backends (GCS, AzureRM, Consul, etc.). The tool claims to detect the backend type (`result.Backend.Type`) but ignores the type and always adds S3/DynamoDB permissions.

**Fix:** Use `result.Backend.Type` to generate the correct backend permissions. For non-AWS backends, skip IAM permissions entirely and note it.

### 13. `--include-state-backend` should be enabled by default

If the goal is generating a policy to **deploy** a stack, the deployer always needs state backend access. The flag should default to `true` or be replaced with `--exclude-state-backend` to opt out.

---

## 🟢 Lower Impact — Code quality & refinements

### 14. Single-file parse failure kills the entire scan

parser.go:87 — `return fmt.Errorf(...)` aborts the entire directory walk if any single `.tf` file fails to parse. One malformed file means zero results.

**Fix:** Log the error to stderr and continue processing other files. Return partial results.

### 15. Output ordering is non-deterministic

`groupActionsByService` (policy.go:153) and `groupActionsByServiceWithActions` (policy.go:183) iterate over Go maps, producing non-deterministic action ordering. The policy JSON changes between runs even for identical inputs.

**Fix:** Sort service names and actions before output, or use an ordered map.

### 16. `extractServicesFromPolicy` parses the output string

main.go:104 — this function parses the generated policy output string to find service names for the summary. It's fragile string parsing that breaks if the output format changes.

**Fix:** Return structured data from `generateIAMPolicy` instead of a raw string, or extract services from the action map before formatting.

### 17. No tests for policy generation or output formats

The test suite only tests the parser and permissions DB loading. There are zero tests for: policy generation, JSON/YAML/Terraform output formats, least-privilege mode, action grouping logic, backend permission logic, or data source permission filtering.

**Fix:** Add table-driven tests for `generateIAMPolicy` covering all three formats, both modes, and edge cases (empty resources, only data sources, backend combinations).

### 18. The fallback parser is too limited for real-world use

`extractWithSimpleParsing` only handles top-level `resource "type" "name"` declarations. It can't handle: inline blocks, `for_each`/`count`, dynamic blocks, or any multi-line attribute. For a production-quality tool, either remove the fallback (fail explicitly and tell the user their HCL is invalid) or invest in a proper fallback.

### 19. No support for `provider` blocks or assume-role configurations

The `provider "aws"` block can specify `assume_role` which requires `sts:AssumeRole`. The tool doesn't detect or generate this permission.

### 20. Docker image runs as non-root but ships Alpine without shell

The Dockerfile creates a non-root `scanner` user (good) but uses Alpine without a shell (the binary is the `ENTRYPOINT`). This is fine for direct runs but makes debugging harder. Consider adding `tini` as the entrypoint for signal handling.

### 21. README claims 135+ resource types; actual is ~80

The README says "Maps 135+ AWS resource types" but the JSON file has 80 unique entries. Either update the count or expand the database.

### 22. `permissions.json` has no schema or validation

Nothing validates the structure of `permissions.json` beyond `jq empty` (well-formed JSON check). A typo like `putBucketPolicy` instead of `PutBucketPolicy` goes undetected. Add JSON Schema validation in CI.

---

## Summary by Priority

| # | Category | Issue |
|---|---|---|
| 1 | 🔴 Critical | Wildcard aggregation grants `service:*` by default |
| 2 | 🔴 Critical | Backend permissions added unconditionally |
| 3 | 🔴 Critical | `iam:PassRole` completely missing |
| 4 | 🔴 Critical | `permissions.json` loaded relative to `$PWD` |
| 5 | 🟠 High | `resource_types` field unused — duplicate ARN map |
| 6 | 🟠 High | Incomplete/incorrect permission mappings |
| 7 | 🟠 High | No `sts:GetCallerIdentity` |
| 8 | 🟠 High | Data source read-permission filtering is broken |
| 9 | 🟡 Medium | No module support |
| 10 | 🟡 Medium | No resource-level ARN scoping |
| 11 | 🟡 Medium | No data source permission entries |
| 12 | 🟡 Medium | Hardcoded S3-only backend permissions |
| 13 | 🟡 Medium | `--include-state-backend` default should be true |
| 14-22 | 🟢 Low | Code quality, testing, documentation |

---

## Recommended First Steps

If you want to fix the critical path first, tackle items in this order:

1. **Fix the wildcard threshold** (#1) — change `>5` to never wildcard, or make it opt-in. This is a one-line change with massive impact.
2. **Fix the backend condition** (#2) — change `||` to just check the flag.
3. **Embed permissions.json** (#4) — use `//go:embed` so the binary is self-contained.
4. **Add `iam:PassRole` and `sts:GetCallerIdentity`** (#3, #7) — add to the permissions DB or generate conditionally.

These four fixes would make the tool produce meaningfully correct least-privilege policies for simple stacks.
