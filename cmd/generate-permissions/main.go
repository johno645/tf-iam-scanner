package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	schemaZipURL = "https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip"
	outputPath   = "/Users/johnsidford/Documents/CLI-Tool/permissions.json"
)

// Schema captures only the fields we need from each CloudFormation resource schema.
type Schema struct {
	TypeName          string              `json:"typeName"`
	Handlers          map[string]struct {
		Permissions []string `json:"permissions"`
	} `json:"handlers"`
	PrimaryIdentifier []string `json:"primaryIdentifier"`
}

// PermissionEntry is the output format for each Terraform resource / data source.
type PermissionEntry struct {
	Actions       []string `json:"actions"`
	ResourceTypes []string `json:"resource_types"`
}

// fullTypeOverrides handles CFN types whose TF names fundamentally deviate
// from the aws_<service>_<resource> pattern. This covers:
//   - EC2 resources that drop the ec2_ prefix (aws_instance, aws_vpc, …)
//   - ELB / ELBv2 resources that use the lb_ / elb_ prefix
//   - Other known irregularities
var fullTypeOverrides = map[string]string{
	// EC2 — these drop the "ec2_" service prefix in Terraform
	"AWS::EC2::Instance":             "aws_instance",
	"AWS::EC2::VPC":                  "aws_vpc",
	"AWS::EC2::Subnet":               "aws_subnet",
	"AWS::EC2::SecurityGroup":        "aws_security_group",
	"AWS::EC2::SecurityGroupEgress":  "aws_security_group_rule",
	"AWS::EC2::SecurityGroupIngress": "aws_security_group_rule",
	"AWS::EC2::NetworkInterface":     "aws_network_interface",
	"AWS::EC2::EIP":                  "aws_eip",
	"AWS::EC2::RouteTable":           "aws_route_table",
	"AWS::EC2::InternetGateway":      "aws_internet_gateway",
	"AWS::EC2::NatGateway":           "aws_nat_gateway",
	"AWS::EC2::Volume":               "aws_ebs_volume",
	"AWS::EC2::VPCEndpoint":              "aws_vpc_endpoint",
	"AWS::EC2::VPCPeeringConnection":     "aws_vpc_peering_connection",
	"AWS::EC2::VPNGateway":               "aws_vpn_gateway",
	"AWS::EC2::VPNConnection":            "aws_vpn_connection",
	"AWS::EC2::CustomerGateway":          "aws_customer_gateway",
	"AWS::EC2::NetworkAcl":               "aws_network_acl",
	"AWS::EC2::PlacementGroup":           "aws_placement_group",
	"AWS::EC2::KeyPair":                  "aws_key_pair",
	"AWS::EC2::SpotFleet":                "aws_spot_fleet_request",
	"AWS::EC2::DHCPOptions":              "aws_vpc_dhcp_options",
	// ELB / ELBv2 — use lb_ / elb_ prefix instead of elastic_load_balancing
	"AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
	"AWS::ElasticLoadBalancing::LoadBalancer":    "aws_elb",
	"AWS::ElasticLoadBalancingV2::Listener":      "aws_lb_listener",
	"AWS::ElasticLoadBalancingV2::TargetGroup":   "aws_lb_target_group",
	"AWS::ElasticLoadBalancingV2::ListenerRule":  "aws_lb_listener_rule",
	// Auto Scaling
	"AWS::AutoScaling::AutoScalingGroup":   "aws_autoscaling_group",
	"AWS::AutoScaling::LaunchConfiguration": "aws_launch_configuration",
	// RDS
	"AWS::RDS::DBInstance":    "aws_db_instance",
	"AWS::RDS::DBCluster":     "aws_rds_cluster",
	"AWS::RDS::DBSubnetGroup": "aws_db_subnet_group",
	// SSM
	"AWS::SSM::Parameter": "aws_ssm_parameter",
	// Route53
	"AWS::Route53::RecordSet":  "aws_route53_record",
	"AWS::Route53::HostedZone": "aws_route53_zone",
	// CloudWatch Logs
	"AWS::Logs::LogGroup": "aws_cloudwatch_log_group",
	// S3 (for correctness — the algorithm also handles this)
	"AWS::S3::Bucket": "aws_s3_bucket",
}

// serviceNameOverrides maps CFN service names to the exact Terraform provider
// service prefix when the general camelToSnake function would produce a
// different result. This covers acronyms that become part of the word
// (DynamoDB→dynamodb) and other naming anomalies (ApiGatewayV2→apigatewayv2).
var serviceNameOverrides = map[string]string{
	"DynamoDB":          "dynamodb",
	"OpenSearchService": "opensearch",
	"Elasticsearch":     "elasticsearch",
	"SecretsManager":    "secretsmanager",
	"CertificateManager": "acm",
	"WAFRegional":        "wafregional",
	"WAFv2":              "wafv2",
	"ApiGatewayV2":       "apigatewayv2",
	"ElasticLoadBalancing": "elastic_load_balancing",
	"AutoScaling":          "autoscaling",
	"ElastiCache":          "elasticache",
	"KinesisFirehose":      "kinesis_firehose",
	"CloudFront":           "cloudfront",
	"CloudWatch":           "cloudwatch",
	"Redshift":             "redshift",
	"ServiceDiscovery":     "service_discovery",
	"StepFunctions":        "sfn",
	"NetworkFirewall":      "networkfirewall",
	"MediaConvert":         "media_convert",
	"MediaStore":           "media_store",
	"StorageGateway":       "storagegateway",
	"CodePipeline":         "codepipeline",
	"CodeDeploy":           "codedeploy",
	"CodeBuild":            "codebuild",
	"CodeCommit":           "codecommit",
	"AppSync":              "appsync",
	"AppMesh":              "appmesh",
	"Pinpoint":             "pinpoint",
	"Amplify":              "amplify",
	"Backup":               "backup",
	"Batch":                "batch",
	"GuardDuty":            "guardduty",
	"SecurityHub":          "securityhub",
	"Inspector":            "inspector",
	"Config":               "config",
	"Shield":               "shield",
	"Transfer":             "transfer",
	"AmazonMQ":             "mq",
	"IoT":                  "iot",
	"Timestream":           "timestreamwrite",
	"DocDB":                "docdb",
	"Neptune":              "neptune",
	"MemoryDB":             "memorydb",
	"QLDB":                 "qldb",
	"FSx":                  "fsx",
	"DataSync":             "datasync",
	"Athena":               "athena",
	"Glue":                 "glue",
	"Events":               "cloudwatch_event",
	"AutoScalingPlans":     "autoscalingplans",
}

// terraformSpecifics defines Terraform-only resources / data sources that have
// no equivalent CloudFormation resource type.
var terraformSpecifics = map[string]PermissionEntry{
	"data.aws_caller_identity": {
		Actions:       []string{"sts:GetCallerIdentity"},
		ResourceTypes: []string{},
	},
	"data.aws_region": {
		Actions:       []string{"ec2:DescribeRegions"},
		ResourceTypes: []string{},
	},
	"data.aws_availability_zones": {
		Actions:       []string{"ec2:DescribeAvailabilityZones"},
		ResourceTypes: []string{},
	},
	"data.aws_ami": {
		Actions:       []string{"ec2:DescribeImages"},
		ResourceTypes: []string{},
	},
	"data.aws_iam_policy_document": {
		Actions:       []string{},
		ResourceTypes: []string{},
	},
	"data.aws_kms_secrets": {
		Actions:       []string{"kms:Decrypt"},
		ResourceTypes: []string{},
	},
	"data.aws_subnet_ids": {
		Actions:       []string{"ec2:DescribeSubnets"},
		ResourceTypes: []string{},
	},
	"aws_s3_bucket_object": {
		Actions:       []string{"s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket"},
		ResourceTypes: []string{},
	},
	"data.aws_s3_bucket_object": {
		Actions:       []string{"s3:GetObject", "s3:ListBucket"},
		ResourceTypes: []string{},
	},
}

func main() {
	fmt.Println("Downloading CloudFormation resource schema zip...")
	resp, err := http.Get(schemaZipURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading schema: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()

	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
		os.Exit(1)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening zip archive: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Downloaded %.1f MB\n", float64(len(zipData))/1024/1024)

	permissions := make(map[string]PermissionEntry)
	processed := 0
	skipped := 0
	nonAWS := 0

	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		schema, err := readSchemaFromZip(f)
		if err != nil {
			skipped++
			continue
		}

		if schema.TypeName == "" {
			continue
		}

		// Only process AWS resource types.
		if !strings.HasPrefix(schema.TypeName, "AWS::") {
			nonAWS++
			continue
		}

		// Skip non-resource types (hooks, modules, helpers).
		if strings.Contains(schema.TypeName, "::Hook::") ||
			strings.Contains(schema.TypeName, "::Module::") ||
			strings.Contains(schema.TypeName, "::Helper::") {
			continue
		}

		tfType := cfnToTerraformType(schema.TypeName)
		if tfType == "" {
			skipped++
			continue
		}

		// Collect all unique IAM actions across all handlers.
		actions := collectAllPermissions(schema.Handlers)
		if len(actions) == 0 {
			skipped++
			continue
		}

		resourceTypes := extractResourceTypes(schema)

		// Resource entry.
		permissions[tfType] = PermissionEntry{
			Actions:       actions,
			ResourceTypes: resourceTypes,
		}

		// Data source entry (read + list permissions only).
		dataActions := collectDataPermissions(schema.Handlers)
		if len(dataActions) > 0 {
			dsKey := "data." + tfType
			permissions[dsKey] = PermissionEntry{
				Actions:       dataActions,
				ResourceTypes: resourceTypes,
			}
		}

		processed++
	}

	// Add Terraform-specific entries not covered by any CFN schema.
	addTerraformSpecifics(permissions)

	if err := writeOutput(permissions); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	dataSourceCount := 0
	for k := range permissions {
		if strings.HasPrefix(k, "data.") {
			dataSourceCount++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  AWS resource types processed: %d\n", processed)
	fmt.Printf("  Non-AWS types skipped:  %d\n", nonAWS)
	fmt.Printf("  Parse/conversion errors:    %d\n", skipped)
	fmt.Printf("  Data source entries:     %d\n", dataSourceCount)
	fmt.Printf("  Total entries in permissions.json: %d\n", len(permissions))
	fmt.Println()
	fmt.Printf("Output written to: %s\n", outputPath)
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

// readSchemaFromZip reads and parses a single schema JSON file from the zip
// using a streaming JSON decoder.
func readSchemaFromZip(f *zip.File) (*Schema, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	var schema Schema
	if err := json.NewDecoder(rc).Decode(&schema); err != nil {
		return nil, err
	}
	return &schema, nil
}

// writeOutput encodes the permissions map as indented JSON and writes it to
// the output path.
func writeOutput(permissions map[string]PermissionEntry) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = outFile.Close() }()

	encoder := json.NewEncoder(outFile)
	encoder.SetIndent("", "  ")
	return encoder.Encode(permissions)
}

// addTerraformSpecifics inserts Terraform-only entries that have no
// corresponding CloudFormation schema.
func addTerraformSpecifics(permissions map[string]PermissionEntry) {
	for key, entry := range terraformSpecifics {
		if _, exists := permissions[key]; !exists {
			permissions[key] = entry
		}
	}
}

// ---------------------------------------------------------------------------
// CFN → Terraform type conversion
// ---------------------------------------------------------------------------

// cfnToTerraformType converts a CloudFormation type name (e.g. "AWS::S3::Bucket")
// to its Terraform AWS provider equivalent (e.g. "aws_s3_bucket").
//
// It first consults the fullTypeOverrides map for known deviations from the
// general pattern, then falls back to the algorithmic conversion:
//
//	aws_<service>_<resource>
//
// The CamelCase-to-snake_case conversion handles multi-word identifiers,
// acronyms, and version suffixes.
func cfnToTerraformType(cfnType string) string {
	// Check full-type overrides first (fundamental pattern deviations).
	if tf, ok := fullTypeOverrides[cfnType]; ok {
		return tf
	}

	parts := strings.Split(cfnType, "::")
	if len(parts) != 3 {
		return ""
	}

	service := parts[1]
	resource := parts[2]

	svcName := convertServiceName(service)
	resName := convertResourceName(resource)

	return fmt.Sprintf("aws_%s_%s", svcName, resName)
}

// convertServiceName converts a CFN service name to the Terraform-appropriate
// snake_case form. It checks the serviceNameOverrides map first, then falls
// back to camelToSnake with version-suffix merging.
func convertServiceName(s string) string {
	if tf, ok := serviceNameOverrides[s]; ok {
		return tf
	}

	result := camelToSnake(s)

	// Merge trailing version suffixes: _v2 → v2, _V3 → v3, etc.
	// This handles services like ElasticLoadBalancingV2, WAFv2, etc.
	re := regexp.MustCompile(`_v(\d+)$`)
	if m := re.FindStringSubmatch(result); m != nil {
		suffix := "v" + m[1]
		result = strings.TrimSuffix(result, "_"+suffix) + suffix
	}

	return result
}

// convertResourceName converts a CFN resource name to its Terraform
// snake_case form.
func convertResourceName(s string) string {
	return camelToSnake(s)
}

// camelToSnake converts a CamelCase identifier to snake_case.
//
// Examples:
//
//	RestApi           → rest_api
//	DBInstance        → db_instance
//	IAMRole           → iam_role
//	DynamoDB          → dynamo_db  (use serviceNameOverrides for dynamodb)
//	S3                → s3
//	S3Bucket          → s3_bucket
//	ApiGatewayV2      → api_gateway_v2 (caller merges _v2 suffix)
func camelToSnake(s string) string {
	if s == "" {
		return ""
	}

	var buf strings.Builder
	runes := []rune(s)
	i := 0

	for i < len(runes) {
		// ---- multi-character uppercase acronym, e.g. "DB" in "DBInstance" ----
		if i+1 < len(runes) && unicode.IsUpper(runes[i]) && unicode.IsUpper(runes[i+1]) {
			end := i + 1
			for end < len(runes) && unicode.IsUpper(runes[end]) {
				end++
			}
			// If the acronym is followed by a lowercase letter, the last
			// uppercase belongs to the next word: "DBInstance" → DB | Instance
			if end < len(runes) && unicode.IsLower(runes[end]) {
				end--
			}
			if end > i {
				if buf.Len() > 0 {
					buf.WriteByte('_')
				}
				buf.WriteString(strings.ToLower(string(runes[i:end])))
				i = end
				continue
			}
		}

		// ---- single uppercase letter ----
		if unicode.IsUpper(runes[i]) {
			if buf.Len() > 0 {
				buf.WriteByte('_')
			}
			buf.WriteRune(unicode.ToLower(runes[i]))
			i++
			continue
		}

		// ---- anything else (lowercase, digits) ----
		buf.WriteRune(runes[i])
		i++
	}

	return buf.String()
}

// ---------------------------------------------------------------------------
// Permission collection
// ---------------------------------------------------------------------------

// collectAllPermissions merges permissions from every handler
// (create, read, update, delete, list) into a sorted, deduplicated slice.
func collectAllPermissions(handlers map[string]struct {
	Permissions []string `json:"permissions"`
}) []string {
	seen := make(map[string]bool)
	for _, h := range handlers {
		for _, p := range h.Permissions {
			seen[normalizeAction(p)] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return sortedKeys(seen)
}

// collectDataPermissions returns only the read + list permissions for data
// source entries.
func collectDataPermissions(handlers map[string]struct {
	Permissions []string `json:"permissions"`
}) []string {
	seen := make(map[string]bool)
	for _, op := range []string{"read", "list"} {
		if h, ok := handlers[op]; ok {
			for _, p := range h.Permissions {
				seen[normalizeAction(p)] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return sortedKeys(seen)
}

// normalizeAction normalizes an IAM action string to lowercase prefix.
// The CloudFormation schema sometimes has uppercase service prefixes
// like "S3:GetObject" → "s3:GetObject".
func normalizeAction(action string) string {
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[0]) + ":" + parts[1]
	}
	return action
}

// ---------------------------------------------------------------------------
// Resource types
// ---------------------------------------------------------------------------

// extractResourceTypes derives a list of resource-type identifiers from the
// schema.  It prefers the primaryIdentifier property name when available,
// otherwise falls back to the resource segment of the CFN type name.
func extractResourceTypes(schema *Schema) []string {
	// Try primaryIdentifier first.
	if len(schema.PrimaryIdentifier) > 0 {
		id := schema.PrimaryIdentifier[0]
		// Format is typically "/properties/BucketName" or "/properties/Id".
		segments := strings.Split(id, "/")
		last := segments[len(segments)-1]
		// Some schemas prefix the property with "$".
		last = strings.TrimPrefix(last, "$")
		if last != "" && !isGenericIdentifier(last) {
			return []string{camelToSnake(last)}
		}
	}

	// Fallback: use the resource part of the CFN type name.
	parts := strings.Split(schema.TypeName, "::")
	if len(parts) == 3 && parts[2] != "" {
		return []string{camelToSnake(parts[2])}
	}

	return []string{}
}

// isGenericIdentifier returns true for identifiers that are too generic to
// use as a resource type hint (e.g., "Id", "Name", "Arn").
func isGenericIdentifier(s string) bool {
	switch s {
	case "Id", "ID", "Name", "Arn", "ARN":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sortedKeys returns the keys of m as a sorted string slice.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
