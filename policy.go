package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// IAMStatement represents an IAM policy statement
type IAMStatement struct {
	Effect   string      `json:"Effect" yaml:"Effect"`
	Action   interface{} `json:"Action" yaml:"Action"`
	Resource interface{} `json:"Resource" yaml:"Resource"`
}

// IAMPolicy represents an IAM policy
type IAMPolicy struct {
	Version   string         `json:"Version" yaml:"Version"`
	Statement []IAMStatement `json:"Statement" yaml:"Statement"`
}

// OutputFormat represents the output format type
type OutputFormat string

const (
	FormatJSON   OutputFormat = "json"
	FormatYAML   OutputFormat = "yaml"
	FormatTerraform OutputFormat = "terraform"
)

// generateIAMPolicy creates an IAM policy based on extracted resources
func generateIAMPolicy(result *ParseResult, includeStateBackend bool, format OutputFormat, leastPrivilege bool) (string, error) {
	actions := make(map[string]bool)

	// Collect actions from resources
	for _, resource := range result.Resources {
		if resource.Provider == "aws" && resource.Type != "" {
			perms := getRequiredPermissions(resource.Type)
			for _, action := range perms {
				actions[action] = true
			}
		}
	}

	// Collect actions from data sources
	for _, dataSource := range result.DataSources {
		if dataSource.Provider == "aws" && dataSource.Type != "" {
			// First, check for data-source-specific permissions entry
			dataSourceKey := "data." + dataSource.Type
			perms := getRequiredPermissions(dataSourceKey)
			if len(perms) > 0 {
				for _, action := range perms {
					actions[action] = true
				}
			} else {
				// Fallback: look up the resource type and filter to read-only actions
				perms := getRequiredPermissions(dataSource.Type)
				for _, action := range perms {
					if isReadOnlyAction(action) {
						actions[action] = true
					}
				}
			}
		}
	}

	// Add Terraform state backend permissions
	if includeStateBackend {
		addBackendPermissions(actions, result.Backend)
	}

	// Always include sts:GetCallerIdentity — the AWS provider requires it on init
	if len(actions) > 0 {
		actions["sts:GetCallerIdentity"] = true
	}

	// Convert to sorted list
	actionList := make([]string, 0, len(actions))
	for action := range actions {
		actionList = append(actionList, action)
	}
	sort.Strings(actionList)

	// Group by service if not using wildcards
	if !leastPrivilege {
		actionList = groupActionsByService(actionList)
	}

	// Create policy statements
	var statements []IAMStatement

	if leastPrivilege {
		// Generate separate statements per service for better granularity
		groupedByService := groupActionsByServiceWithActions(actionList)
		for service, serviceActions := range groupedByService {
			resource := getResourceARNForService(service)
			
			statement := IAMStatement{
				Effect:   "Allow",
				Action:   serviceActions,
				Resource: resource,
			}
			statements = append(statements, statement)
		}
		sort.Slice(statements, func(i, j int) bool {
			// Sort by first action alphabetically
			iActions := statements[i].Action.([]string)
			jActions := statements[j].Action.([]string)
			if len(iActions) > 0 && len(jActions) > 0 {
				return iActions[0] < jActions[0]
			}
			return false
		})
	} else {
		// Single statement with all actions
		statement := IAMStatement{
			Effect:   "Allow",
			Action:   actionList,
			Resource: "*",
		}
		statements = []IAMStatement{statement}
	}

	policy := IAMPolicy{
		Version:   "2012-10-17",
		Statement: statements,
	}

	// Format output based on requested format
	switch format {
	case FormatJSON:
		jsonBytes, err := json.MarshalIndent(policy, "", "  ")
		if err != nil {
			return "", fmt.Errorf("error marshaling policy to JSON: %w", err)
		}
		return string(jsonBytes), nil

	case FormatYAML:
		yamlBytes, err := yaml.Marshal(&policy)
		if err != nil {
			return "", fmt.Errorf("error marshaling policy to YAML: %w", err)
		}
		return string(yamlBytes), nil

	case FormatTerraform:
		return generateTerraformOutput(statements), nil

	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// groupActionsByService groups actions by AWS service without wildcarding
func groupActionsByService(actions []string) []string {
	servicePrefixes := make(map[string][]string)

	for _, action := range actions {
		parts := strings.Split(action, ":")
		if len(parts) == 2 {
			service := parts[0]
			servicePrefixes[service] = append(servicePrefixes[service], parts[1])
		} else {
			// If action doesn't have service:action format, keep as is
			return actions
		}
	}

	grouped := []string{}
	for service, actionNames := range servicePrefixes {
		for _, actionName := range actionNames {
			grouped = append(grouped, service+":"+actionName)
		}
	}
	sort.Strings(grouped)
	return grouped
}

// groupActionsByServiceWithActions returns actions grouped by service, sorted within each group.
func groupActionsByServiceWithActions(actions []string) map[string][]string {
	grouped := make(map[string][]string)

	for _, action := range actions {
		parts := strings.Split(action, ":")
		if len(parts) == 2 {
			service := parts[0]
			grouped[service] = append(grouped[service], action)
		}
	}

	// Sort actions within each service group for deterministic output
	for service := range grouped {
		sort.Strings(grouped[service])
	}

	return grouped
}

// isReadOnlyAction returns true if an IAM action is read-only (does not mutate resources).
func isReadOnlyAction(action string) bool {
	readPrefixes := []string{
		"Get", "List", "Describe", "Head", "Read", "Query", "Scan",
		"Check", "Validate", "Verify", "Search", "View", "Lookup",
	}
	parts := strings.Split(action, ":")
	if len(parts) != 2 {
		return false
	}
	actionName := parts[1]
	for _, prefix := range readPrefixes {
		if strings.HasPrefix(actionName, prefix) {
			return true
		}
	}
	return false
}

// getResourceARNForService returns the appropriate resource ARN for a service
// using resource_types from the permissions database when available.
func getResourceARNForService(service string) string {
	// Collect resource_types from entries belonging to this service.
	// An entry "belongs" to a service if its first action is in that service.
	resourceTypes := make(map[string]bool)
	for resourceType, perms := range permissionsDB {
		if !strings.HasPrefix(resourceType, "aws_") || len(perms.ResourceTypes) == 0 {
			continue
		}
		if len(perms.Actions) == 0 {
			continue
		}
		// Determine which service this entry's primary actions belong to
		firstAction := perms.Actions[0]
		parts := strings.Split(firstAction, ":")
		if len(parts) == 2 && parts[0] == service {
			for _, rt := range perms.ResourceTypes {
				resourceTypes[rt] = true
			}
		}
	}

	// If we have resource types, construct ARN patterns from them.
	// When only one resource type is found, use a specific pattern.
	// When multiple are found, fall back to the service-level default
	// since the actions span multiple resource types.
	if len(resourceTypes) == 1 {
		for rt := range resourceTypes {
			pattern := constructARNPattern(service, rt)
			if pattern != "*" {
				return pattern
			}
		}
	}

	// Fallback: per-service ARN patterns
	return defaultARNForService(service)
}

// constructARNPattern builds an ARN pattern from a service and resource type name.
func constructARNPattern(service, resourceType string) string {
	// Services with ARN formats that omit region or account
	switch service {
	case "s3":
		return fmt.Sprintf("arn:aws:s3:::%s", resourceType)
	case "iam":
		return fmt.Sprintf("arn:aws:iam::*:%s", resourceType)
	case "route53":
		return "arn:aws:route53:::*"
	case "cloudfront":
		return "arn:aws:cloudfront:::*"
	case "waf":
		return "arn:aws:waf:::*"
	case "shield":
		return "arn:aws:shield:::*"
	}

	// Standard ARN format: arn:aws:<service>:<region>:<account>:<resource_type>
	// Map resource type names to their ARN path segments
	arnPath := resourceTypeARNPath(resourceType)
	if arnPath != "" {
		return fmt.Sprintf("arn:aws:%s:*:*:%s", service, arnPath)
	}

	return fmt.Sprintf("arn:aws:%s:*:*:*", service)
}

// resourceTypeARNPath maps resource_type values to their ARN path components.
func resourceTypeARNPath(rt string) string {
	paths := map[string]string{
		"bucket":            "bucket",
		"instance":          "instance",
		"vpc":               "vpc",
		"subnet":            "subnet",
		"security-group":    "security-group",
		"route-table":       "route-table",
		"internet-gateway":  "internet-gateway",
		"nat-gateway":       "nat-gateway",
		"elastic-ip":        "elastic-ip",
		"transit-gateway":   "transit-gateway",
		"db":                "db",
		"cluster":           "cluster",
		"function":          "function",
		"restapis":          "restapis",
		"api":               "apis",
		"topic":             "topic",
		"queue":             "queue",
		"table":             "table",
		"log-group":         "log-group",
		"alarm":             "alarm",
		"loadbalancer":      "loadbalancer",
		"file-system":       "file-system",
		"secret":            "secret",
		"key":               "key",
		"repository":        "repository",
		"hostedzone":        "hostedzone",
		"distribution":      "distribution",
		"user":              "user",
		"role":              "role",
		"policy":            "policy",
		"instance-profile":  "instance-profile",
		"detector":          "detector",
		"document":          "document",
		"server":            "server",
		"broker":            "broker",
		"certificate":       "certificate",
		"container":         "container",
		"mesh":              "mesh",
		"service":           "service",
		"task":              "task",
		"job":               "job",
		"crawler":           "crawler",
		"backup-vault":      "backup-vault",
		"backup-plan":       "backup-plan",
		"pipeline":          "pipeline",
		"application":       "application",
		"project":           "project",
		"rule":              "rule",
		"config-rule":       "config-rule",
		"firewall":          "firewall",
		"app":               "apps",
		"graphql-api":       "apis",
		"userpool":          "userpool",
		"identitypool":      "identitypool",
		"ledger":            "ledger",
		"database":          "database",
		"stateMachine":      "stateMachine",
		"stream":            "stream",
		"deliverystream":    "deliverystream",
		"domain":            "domain",
		"gateway":           "gateway",
	}
	if path, ok := paths[rt]; ok {
		return path
	}
	return ""
}

// defaultARNForService provides a fallback ARN pattern for services not covered
// by the resource_type-based construction.
func defaultARNForService(service string) string {
	arnMap := map[string]string{
		"ec2":                      "arn:aws:ec2:*:*:*",
		"s3":                       "arn:aws:s3:::*",
		"iam":                      "arn:aws:iam::*:*",
		"rds":                      "arn:aws:rds:*:*:*",
		"lambda":                   "arn:aws:lambda:*:*:*",
		"apigateway":               "arn:aws:apigateway:*::*",
		"sns":                      "arn:aws:sns:*:*:*",
		"sqs":                      "arn:aws:sqs:*:*:*",
		"dynamodb":                 "arn:aws:dynamodb:*:*:*",
		"logs":                     "arn:aws:logs:*:*:*",
		"cloudwatch":               "arn:aws:cloudwatch:*:*:*",
		"autoscaling":              "arn:aws:autoscaling:*:*:*",
		"application-autoscaling":  "arn:aws:application-autoscaling:*:*:*",
		"route53":                  "arn:aws:route53:::*",
		"cloudfront":               "arn:aws:cloudfront:::*",
		"elasticloadbalancing":     "arn:aws:elasticloadbalancing:*:*:*",
		"elasticfilesystem":        "arn:aws:elasticfilesystem:*:*:*",
		"secretsmanager":           "arn:aws:secretsmanager:*:*:*",
		"kms":                      "arn:aws:kms:*:*:*",
		"ecr":                      "arn:aws:ecr:*:*:repository/*",
		"ecs":                      "arn:aws:ecs:*:*:*",
		"eks":                      "arn:aws:eks:*:*:cluster/*",
		"events":                   "arn:aws:events:*:*:rule/*",
		"codepipeline":             "arn:aws:codepipeline:*:*:*",
		"codedeploy":               "arn:aws:codedeploy:*:*:*",
		"codebuild":                "arn:aws:codebuild:*:*:project/*",
		"codecommit":               "arn:aws:codecommit:*:*:*",
		"glue":                     "arn:aws:glue:*:*:*",
		"redshift":                 "arn:aws:redshift:*:*:cluster:*",
		"elasticache":              "arn:aws:elasticache:*:*:*",
		"es":                       "arn:aws:es:*:*:domain/*",
		"kinesis":                  "arn:aws:kinesis:*:*:stream/*",
		"firehose":                 "arn:aws:firehose:*:*:deliverystream/*",
		"athena":                   "arn:aws:athena:*:*:workgroup/*",
		"datasync":                 "arn:aws:datasync:*:*:*",
		"backup":                   "arn:aws:backup:*:*:*",
		"batch":                    "arn:aws:batch:*:*:*",
		"guardduty":                "arn:aws:guardduty:*:*:detector/*",
		"securityhub":              "arn:aws:securityhub:*:*:hub/default",
		"inspector":                "arn:aws:inspector:*:*:*",
		"config":                   "arn:aws:config:*:*:*",
		"waf":                      "arn:aws:waf:::*",
		"waf-regional":             "arn:aws:waf-regional:*:*:*",
		"wafv2":                    "arn:aws:wafv2:*:*:*",
		"shield":                   "arn:aws:shield:::*",
		"ssm":                      "arn:aws:ssm:*:*:*",
		"transfer":                 "arn:aws:transfer:*:*:server/*",
		"mq":                       "arn:aws:mq:*:*:broker/*",
		"iot":                      "arn:aws:iot:*:*:*",
		"mobiletargeting":          "arn:aws:mobiletargeting:*:*:apps/*",
		"mediaconvert":             "arn:aws:mediaconvert:*:*:queues/*",
		"mediastore":               "arn:aws:mediastore:*:*:container/*",
		"storagegateway":           "arn:aws:storagegateway:*:*:gateway/*",
		"servicediscovery":         "arn:aws:servicediscovery:*:*:*",
		"appmesh":                  "arn:aws:appmesh:*:*:mesh/*",
		"states":                   "arn:aws:states:*:*:stateMachine:*",
		"network-firewall":         "arn:aws:network-firewall:*:*:*",
		"amplify":                  "arn:aws:amplify:*:*:*",
		"appsync":                  "arn:aws:appsync:*:*:apis/*",
		"cognito-idp":              "arn:aws:cognito-idp:*:*:userpool/*",
		"cognito-identity":         "arn:aws:cognito-identity:*:*:identitypool/*",
		"fsx":                      "arn:aws:fsx:*:*:file-system/*",
		"qldb":                     "arn:aws:qldb:*:*:*",
		"timestream":               "arn:aws:timestream:*:*:*",
		"memorydb":                 "arn:aws:memorydb:*:*:cluster/*",
		"sts":                      "*",
	}
	if arn, exists := arnMap[service]; exists {
		return arn
	}
	return "*"
}

// addBackendPermissions adds the appropriate IAM permissions for the detected state backend.
func addBackendPermissions(actions map[string]bool, backend *BackendConfig) {
	if backend == nil {
		// Default to S3 backend (most common)
		backendActions := []string{
			"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject",
			"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:DescribeTable",
		}
		for _, action := range backendActions {
			actions[action] = true
		}
		return
	}

	switch backend.Type {
	case "s3":
		backendActions := []string{
			"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject",
			"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:DescribeTable",
		}
		for _, action := range backendActions {
			actions[action] = true
		}
		// Add DynamoDB table creation for lock table
		if backend.Config["dynamodb_table"] != "" {
			actions["dynamodb:CreateTable"] = true
		}
	case "gcs", "azurerm", "consul", "kubernetes", "oss", "pg", "http", "local":
		// Non-AWS backends — no additional IAM permissions needed
		// Note it but don't add anything
	default:
		// Unknown backend type — add common S3/DynamoDB defaults conservatively
		backendActions := []string{
			"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject",
			"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:DescribeTable",
		}
		for _, action := range backendActions {
			actions[action] = true
		}
	}
}

// generateTerraformOutput generates Terraform HCL output
func generateTerraformOutput(statements []IAMStatement) string {
	var sb strings.Builder

	sb.WriteString("data \"aws_iam_policy_document\" \"generated\" {\n")

	for i, statement := range statements {
		sb.WriteString("  statement {\n")
		fmt.Fprintf(&sb, "    effect = \"%s\"\n", statement.Effect)

		// Handle Action (can be string or array)
		switch v := statement.Action.(type) {
		case []string:
			if len(v) > 0 {
				sb.WriteString("    actions = [\n")
				for _, action := range v {
					fmt.Fprintf(&sb, "      \"%s\",\n", action)
				}
				sb.WriteString("    ]\n")
			}
		case string:
			fmt.Fprintf(&sb, "    actions = [\"%s\"]\n", v)
		}

		// Handle Resource
		switch v := statement.Resource.(type) {
		case []string:
			if len(v) > 0 {
				sb.WriteString("    resources = [\n")
				for _, resource := range v {
					fmt.Fprintf(&sb, "      \"%s\",\n", resource)
				}
				sb.WriteString("    ]\n")
			}
		case string:
			fmt.Fprintf(&sb, "    resources = [\"%s\"]\n", v)
		}

		sb.WriteString("  }")
		if i < len(statements)-1 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n}\n")
	sb.WriteString("\nresource \"aws_iam_policy\" \"generated\" {\n")
	sb.WriteString("  name   = \"tf-iam-scanner-generated\"\n")
	sb.WriteString("  policy = data.aws_iam_policy_document.generated.json\n")
	sb.WriteString("}\n")

	return sb.String()
}
