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
			// For data sources, we typically need read permissions
			resourceType := strings.TrimPrefix(dataSource.Type, "data.")
			perms := getRequiredPermissions(resourceType)
			// Filter to read-only actions
			for _, action := range perms {
				if strings.Contains(action, "Describe") || 
				   strings.Contains(action, "Get") || 
				   strings.Contains(action, "List") {
					actions[action] = true
				}
			}
		}
	}

	// Add Terraform state backend permissions
	if includeStateBackend || result.Backend != nil {
		backendActions := []string{
			"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject",
			"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:DescribeTable",
		}
		for _, action := range backendActions {
			actions[action] = true
		}
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

// groupActionsByService groups actions by AWS service and uses wildcards where appropriate
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
		// Check if we should use wildcard (if more than 5 actions for a service)
		if len(actionNames) > 5 {
			grouped = append(grouped, service+":*")
		} else {
			for _, actionName := range actionNames {
				grouped = append(grouped, service+":"+actionName)
			}
		}
	}

	return grouped
}

// groupActionsByServiceWithActions returns actions grouped by service
func groupActionsByServiceWithActions(actions []string) map[string][]string {
	grouped := make(map[string][]string)

	for _, action := range actions {
		parts := strings.Split(action, ":")
		if len(parts) == 2 {
			service := parts[0]
			grouped[service] = append(grouped[service], action)
		}
	}

	return grouped
}

// getResourceARNForService returns the appropriate resource ARN for a service
func getResourceARNForService(service string) string {
	// Map services to their ARN patterns
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
		"mobiletargeting":         "arn:aws:mobiletargeting:*:*:apps/*",
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
	}

	if arn, exists := arnMap[service]; exists {
		return arn
	}

	return "*"
}

// generateTerraformOutput generates Terraform HCL output
func generateTerraformOutput(statements []IAMStatement) string {
	var sb strings.Builder

	sb.WriteString("data \"aws_iam_policy_document\" \"generated\" {\n")

	for i, statement := range statements {
		sb.WriteString("  statement {\n")
		sb.WriteString(fmt.Sprintf("    effect = \"%s\"\n", statement.Effect))

		// Handle Action (can be string or array)
		switch v := statement.Action.(type) {
		case []string:
			if len(v) > 0 {
				sb.WriteString("    actions = [\n")
				for _, action := range v {
					sb.WriteString(fmt.Sprintf("      \"%s\",\n", action))
				}
				sb.WriteString("    ]\n")
			}
		case string:
			sb.WriteString(fmt.Sprintf("    actions = [\"%s\"]\n", v))
		}

		// Handle Resource
		switch v := statement.Resource.(type) {
		case []string:
			if len(v) > 0 {
				sb.WriteString("    resources = [\n")
				for _, resource := range v {
					sb.WriteString(fmt.Sprintf("      \"%s\",\n", resource))
				}
				sb.WriteString("    ]\n")
			}
		case string:
			sb.WriteString(fmt.Sprintf("    resources = [\"%s\"]\n", v))
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
