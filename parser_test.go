package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseSimpleTerraformFile(t *testing.T) {
	result, err := parseTerraformFiles("test-fixtures/simple")
	if err != nil {
		t.Fatalf("Error parsing simple terraform files: %v", err)
	}

	if len(result.Resources) == 0 {
		t.Error("Expected to find resources, got 0")
	}

	foundS3 := false
	foundLambda := false

	for _, resource := range result.Resources {
		if resource.Type == "aws_s3_bucket" {
			foundS3 = true
		}
		if resource.Type == "aws_lambda_function" {
			foundLambda = true
		}
	}

	if !foundS3 {
		t.Error("Expected to find aws_s3_bucket")
	}

	if !foundLambda {
		t.Error("Expected to find aws_lambda_function")
	}
}

func TestParseComplexTerraformFile(t *testing.T) {
	result, err := parseTerraformFiles("test-fixtures/complex")
	if err != nil {
		t.Fatalf("Error parsing complex terraform files: %v", err)
	}

	if len(result.Resources) < 10 {
		t.Errorf("Expected to find many resources, got %d", len(result.Resources))
	}

	foundVPC := false
	for _, resource := range result.Resources {
		if resource.Type == "aws_vpc" {
			foundVPC = true
			break
		}
	}

	if !foundVPC {
		t.Error("Expected to find aws_vpc")
	}
}

func TestBackendDetection(t *testing.T) {
	result, err := parseTerraformFiles("test-fixtures/backend")
	if err != nil {
		t.Fatalf("Error parsing backend terraform files: %v", err)
	}

	if result.Backend == nil {
		t.Error("Expected to detect backend configuration")
	}

	if result.Backend.Type != "s3" {
		t.Errorf("Expected backend type to be s3, got %s", result.Backend.Type)
	}
}

func TestPermissionsDB(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	if permissionsDB == nil {
		t.Fatal("Permissions DB is nil")
	}

	perms, exists := permissionsDB["aws_s3_bucket"]
	if !exists {
		t.Error("aws_s3_bucket should exist in permissions DB")
	}

	if len(perms.Actions) == 0 {
		t.Error("aws_s3_bucket should have actions defined")
	}
}

func TestGetRequiredPermissions(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	actions := getRequiredPermissions("aws_lambda_function")
	if len(actions) == 0 {
		t.Error("Expected to get permissions for aws_lambda_function")
	}

	hasCreateFunction := false
	for _, action := range actions {
		if action == "lambda:CreateFunction" {
			hasCreateFunction = true
			break
		}
	}

	if !hasCreateFunction {
		t.Error("Expected to find lambda:CreateFunction in permissions")
	}
}

// --- Policy Generation Tests ---

func TestGenerateIAMPolicyJSON(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_s3_bucket", Name: "test", Provider: "aws", ResourceType: "aws_s3_bucket"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if !strings.Contains(policy, "s3:CreateBucket") {
		t.Error("Expected policy to contain s3:CreateBucket")
	}
	if !strings.Contains(policy, "sts:GetCallerIdentity") {
		t.Error("Expected policy to contain sts:GetCallerIdentity")
	}
	if strings.Contains(policy, "s3:*") {
		t.Error("Policy should not contain wildcarded service actions")
	}

	var iamPolicy IAMPolicy
	if err := json.Unmarshal([]byte(policy), &iamPolicy); err != nil {
		t.Fatalf("Generated policy is not valid JSON: %v", err)
	}

	if iamPolicy.Version != "2012-10-17" {
		t.Errorf("Expected Version '2012-10-17', got '%s'", iamPolicy.Version)
	}
	if len(iamPolicy.Statement) == 0 {
		t.Error("Expected at least one statement")
	}
	if iamPolicy.Statement[0].Effect != "Allow" {
		t.Error("Expected Effect 'Allow'")
	}
}

func TestGenerateIAMPolicyYAML(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_s3_bucket", Name: "test", Provider: "aws", ResourceType: "aws_s3_bucket"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatYAML, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if !strings.Contains(policy, "s3:CreateBucket") {
		t.Error("Expected YAML policy to contain s3:CreateBucket")
	}
	if !strings.Contains(policy, "Allow") {
		t.Error("Expected YAML policy to contain 'Allow'")
	}
}

func TestGenerateIAMPolicyTerraform(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_s3_bucket", Name: "test", Provider: "aws", ResourceType: "aws_s3_bucket"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatTerraform, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if !strings.Contains(policy, "aws_iam_policy_document") {
		t.Error("Expected Terraform output to contain aws_iam_policy_document")
	}
	if !strings.Contains(policy, "s3:CreateBucket") {
		t.Error("Expected Terraform output to contain s3:CreateBucket")
	}
	if !strings.Contains(policy, "aws_iam_policy") {
		t.Error("Expected Terraform output to contain aws_iam_policy resource")
	}
}

// --- No Wildcards Test ---

func TestNoServiceWildcards(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	// With multiple resources from same service, should not wildcard
	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_vpc", Name: "main", Provider: "aws", ResourceType: "aws_vpc"},
			{Type: "aws_subnet", Name: "sub", Provider: "aws", ResourceType: "aws_subnet"},
			{Type: "aws_security_group", Name: "sg", Provider: "aws", ResourceType: "aws_security_group"},
			{Type: "aws_internet_gateway", Name: "igw", Provider: "aws", ResourceType: "aws_internet_gateway"},
			{Type: "aws_instance", Name: "web", Provider: "aws", ResourceType: "aws_instance"},
			{Type: "aws_eip", Name: "ip", Provider: "aws", ResourceType: "aws_eip"},
			{Type: "aws_nat_gateway", Name: "nat", Provider: "aws", ResourceType: "aws_nat_gateway"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	// With 7+ EC2 resources, the old code would wildcard to ec2:*
	// New code should list individual actions
	if strings.Contains(policy, "ec2:*") {
		t.Error("Policy should not contain ec2:* wildcard even with many EC2 resources")
	}

	// Verify individual EC2 actions are present
	if !strings.Contains(policy, "ec2:CreateVpc") {
		t.Error("Expected ec2:CreateVpc")
	}
	if !strings.Contains(policy, "ec2:RunInstances") {
		t.Error("Expected ec2:RunInstances")
	}
}

// --- Backend Permission Tests ---

func TestBackendPermissionsIncluded(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_s3_bucket", Name: "test", Provider: "aws", ResourceType: "aws_s3_bucket"},
		},
		Backend: &BackendConfig{Type: "s3", Config: map[string]string{"bucket": "state"}},
	}

	policy, err := generateIAMPolicy(result, true, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if !strings.Contains(policy, "s3:GetObject") {
		t.Error("Expected s3:GetObject when backend permissions included")
	}
	if !strings.Contains(policy, "dynamodb:GetItem") {
		t.Error("Expected dynamodb:GetItem when backend permissions included")
	}
}

func TestBackendPermissionsExcluded(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_s3_bucket", Name: "test", Provider: "aws", ResourceType: "aws_s3_bucket"},
		},
		Backend: &BackendConfig{Type: "s3", Config: map[string]string{"bucket": "state"}},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	// S3 bucket actions for the resource itself (CreateBucket, etc.) should be there
	// but NOT the backend-specific ones like GetObject (which is from s3_bucket_object)
	// Actually GetObject might be there from s3_bucket_object... let's check for
	// dynamodb:GetItem specifically since there's no dynamodb resource
	if strings.Contains(policy, "dynamodb:GetItem") {
		t.Error("Should not include dynamodb backend actions when flag is false")
	}
}

// --- STS Tests ---

func TestSTSIncluded(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_s3_bucket", Name: "test", Provider: "aws", ResourceType: "aws_s3_bucket"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if !strings.Contains(policy, "sts:GetCallerIdentity") {
		t.Error("Expected sts:GetCallerIdentity in all policies with AWS resources")
	}
}

func TestSTSNotIncludedWhenEmpty(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources:   []Resource{},
		DataSources: []Resource{},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if strings.Contains(policy, "sts:GetCallerIdentity") {
		t.Error("Should not include sts:GetCallerIdentity when no AWS resources")
	}
}

// --- Least-Privilege Mode Tests ---

func TestLeastPrivilegeMode(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_s3_bucket", Name: "test", Provider: "aws", ResourceType: "aws_s3_bucket"},
			{Type: "aws_lambda_function", Name: "fn", Provider: "aws", ResourceType: "aws_lambda_function"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, true)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	var iamPolicy IAMPolicy
	if err := json.Unmarshal([]byte(policy), &iamPolicy); err != nil {
		t.Fatalf("Generated policy is not valid JSON: %v", err)
	}

	// Should have multiple statements: s3, lambda, sts
	if len(iamPolicy.Statement) < 2 {
		t.Errorf("Expected at least 2 statements in least-privilege mode, got %d", len(iamPolicy.Statement))
	}

	// Each non-STS statement should have specific resource ARNs (not "*")
	for _, stmt := range iamPolicy.Statement {
		resource, ok := stmt.Resource.(string)
		if !ok {
			continue
		}
		if resource == "*" {
			// sts has resource "*" by default — that's acceptable
			if actions, ok := stmt.Action.([]string); ok {
				allSTS := true
				for _, a := range actions {
					if !strings.HasPrefix(a, "sts:") {
						allSTS = false
						break
					}
				}
				if !allSTS {
					t.Errorf("Expected specific ARN for non-STS statement, got * for: %v", actions)
				}
			}
		}
	}
}

// --- PassRole Tests ---

func TestPassRoleIncluded(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	// aws_lambda_function has iam:PassRole in its permissions
	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_lambda_function", Name: "fn", Provider: "aws", ResourceType: "aws_lambda_function"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if !strings.Contains(policy, "iam:PassRole") {
		t.Error("Expected iam:PassRole for lambda function resource")
	}
}

// --- Data Source Tests ---

func TestDataSourcePermissions(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		DataSources: []Resource{
			{Type: "aws_caller_identity", Name: "current", Provider: "aws", ResourceType: "aws_caller_identity"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	if !strings.Contains(policy, "sts:GetCallerIdentity") {
		t.Error("Expected sts:GetCallerIdentity for aws_caller_identity data source")
	}
}

func TestDataSourceReadOnlyFiltering(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	// Data source for a resource type without a data.* entry:
	// should filter to read-only actions using isReadOnlyAction
	result := &ParseResult{
		DataSources: []Resource{
			{Type: "aws_security_group", Name: "sg", Provider: "aws", ResourceType: "aws_security_group"},
		},
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, false)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	// Should contain DescribeSecurityGroups (read-only)
	if !strings.Contains(policy, "ec2:DescribeSecurityGroups") {
		t.Error("Expected ec2:DescribeSecurityGroups for data source")
	}
	// Should NOT contain CreateSecurityGroup (write operation)
	if strings.Contains(policy, "ec2:CreateSecurityGroup") {
		t.Error("Should not include write actions for data sources")
	}
}

// --- isReadOnlyAction Tests ---

func TestIsReadOnlyAction(t *testing.T) {
	tests := []struct {
		action   string
		readOnly bool
	}{
		{"ec2:DescribeInstances", true},
		{"ec2:RunInstances", false},
		{"s3:GetObject", true},
		{"s3:PutObject", false},
		{"s3:ListBucket", true},
		{"s3:DeleteBucket", false},
		{"s3:HeadBucket", true},
		{"iam:GetRole", true},
		{"iam:CreateRole", false},
		{"kms:Decrypt", false},
		{"dynamodb:Query", true},
		{"dynamodb:Scan", true},
		{"logs:DescribeLogGroups", true},
		{"cloudwatch:PutMetricAlarm", false},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			result := isReadOnlyAction(tt.action)
			if result != tt.readOnly {
				t.Errorf("isReadOnlyAction(%q) = %v, want %v", tt.action, result, tt.readOnly)
			}
		})
	}
}

// --- Module Source Extraction Tests ---

func TestModuleSourceExtraction(t *testing.T) {
	content := []byte(`
module "vpc" {
  source = "./modules/vpc"
  cidr   = "10.0.0.0/16"
}

resource "aws_s3_bucket" "data" {
  bucket = "test"
}
`)

	result, err := extractWithSimpleParsing(content, "test.tf")
	if err != nil {
		t.Fatalf("Error parsing: %v", err)
	}

	foundModule := false
	for _, mod := range result.Modules {
		if mod == "./modules/vpc" {
			foundModule = true
		}
	}
	if !foundModule {
		t.Errorf("Expected to find module source './modules/vpc', got %v", result.Modules)
	}
}

func TestIsLocalModuleSource(t *testing.T) {
	tests := []struct {
		source string
		local  bool
	}{
		{"./modules/vpc", true},
		{"../shared/networking", true},
		{"/absolute/path", true},
		{"terraform-aws-modules/vpc/aws", false},
		{"git::https://github.com/org/repo.git", false},
		{"hashicorp/consul/aws", false},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			result := isLocalModuleSource(tt.source)
			if result != tt.local {
				t.Errorf("isLocalModuleSource(%q) = %v, want %v", tt.source, result, tt.local)
			}
		})
	}
}

// --- Embed Test ---

func TestPermissionsDBEmbedded(t *testing.T) {
	if len(embeddedPermissionsDB) == 0 {
		t.Error("embeddedPermissionsDB should not be empty")
	}

	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading embedded permissions DB: %v", err)
	}

	// Verify data source entries exist
	dsActions := getRequiredPermissions("data.aws_caller_identity")
	if len(dsActions) == 0 {
		t.Error("Expected data.aws_caller_identity to have actions")
	}
	if dsActions[0] != "sts:GetCallerIdentity" {
		t.Errorf("Expected sts:GetCallerIdentity, got %v", dsActions)
	}
}

// --- Non-Deterministic Output Test ---

func TestDeterministicOutput(t *testing.T) {
	if err := loadPermissionsDB(); err != nil {
		t.Fatalf("Error loading permissions DB: %v", err)
	}

	result := &ParseResult{
		Resources: []Resource{
			{Type: "aws_vpc", Name: "main", Provider: "aws", ResourceType: "aws_vpc"},
			{Type: "aws_subnet", Name: "sub", Provider: "aws", ResourceType: "aws_subnet"},
			{Type: "aws_instance", Name: "web", Provider: "aws", ResourceType: "aws_instance"},
		},
	}

	// Generate policy twice — output should be identical
	policy1, _ := generateIAMPolicy(result, false, FormatJSON, false)
	policy2, _ := generateIAMPolicy(result, false, FormatJSON, false)

	if policy1 != policy2 {
		t.Error("Policy generation should be deterministic — two runs produced different output")
	}
}

// --- Plan File Tests ---

func TestParsePlanFile(t *testing.T) {
	result, err := parsePlanFile("test-fixtures/plan/tfplan.json")
	if err != nil {
		t.Fatalf("Error parsing plan file: %v", err)
	}

	if len(result.Resources) == 0 {
		t.Error("Expected to find resources in plan file")
	}

	// Should find resources from root module (3) + child_modules (2)
	if len(result.Resources) < 5 {
		t.Errorf("Expected at least 5 resources, got %d", len(result.Resources))
	}

	// Check for module resources
	foundVPC := false
	foundSubnet := false
	for _, r := range result.Resources {
		if r.Type == "aws_vpc" {
			foundVPC = true
		}
		if r.Type == "aws_subnet" {
			foundSubnet = true
		}
	}
	if !foundVPC {
		t.Error("Expected to find aws_vpc from module in plan file")
	}
	if !foundSubnet {
		t.Error("Expected to find aws_subnet from module in plan file")
	}

	// Should have data sources
	if len(result.DataSources) < 1 {
		t.Error("Expected at least 1 data source in plan file")
	}

	foundCallerIdentity := false
	for _, ds := range result.DataSources {
		if ds.Type == "aws_caller_identity" {
			foundCallerIdentity = true
		}
	}
	if !foundCallerIdentity {
		t.Error("Expected data.aws_caller_identity in plan file")
	}
}

func TestParsePlanFileModuleSources(t *testing.T) {
	result, err := parsePlanFile("test-fixtures/plan/tfplan.json")
	if err != nil {
		t.Fatalf("Error parsing plan file: %v", err)
	}

	// Should extract local module source from configuration
	foundModule := false
	for _, mod := range result.Modules {
		if mod == "./modules/vpc" {
			foundModule = true
		}
	}
	if !foundModule {
		t.Errorf("Expected to find './modules/vpc' module source, got %v", result.Modules)
	}
}

func TestPlanFilePolicyGeneration(t *testing.T) {
	result, err := parsePlanFile("test-fixtures/plan/tfplan.json")
	if err != nil {
		t.Fatalf("Error parsing plan file: %v", err)
	}

	policy, err := generateIAMPolicy(result, false, FormatJSON, true)
	if err != nil {
		t.Fatalf("Error generating policy: %v", err)
	}

	// Plan has S3, Lambda, IAM, VPC, Subnet resources
	if !strings.Contains(policy, "s3:CreateBucket") {
		t.Error("Expected s3:CreateBucket from plan")
	}
	if !strings.Contains(policy, "lambda:CreateFunction") {
		t.Error("Expected lambda:CreateFunction from plan")
	}
	if !strings.Contains(policy, "iam:CreateRole") {
		t.Error("Expected iam:CreateRole from plan")
	}
	if !strings.Contains(policy, "ec2:CreateVpc") {
		t.Error("Expected ec2:CreateVpc from module in plan")
	}

	// Data source aws_caller_identity should contribute sts:GetCallerIdentity
	if !strings.Contains(policy, "sts:GetCallerIdentity") {
		t.Error("Expected sts:GetCallerIdentity from data source in plan")
	}

	// Least-privilege should produce multiple statements
	var iamPolicy IAMPolicy
	if err := json.Unmarshal([]byte(policy), &iamPolicy); err != nil {
		t.Fatalf("Generated policy is not valid JSON: %v", err)
	}
	if len(iamPolicy.Statement) < 4 {
		t.Errorf("Expected >=4 statements in least-privilege mode, got %d", len(iamPolicy.Statement))
	}
}

// Test helper function
func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	// Cleanup if needed
	os.Exit(code)
}
