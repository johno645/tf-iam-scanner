package main

import (
	"os"
	"testing"
)

func TestParseSimpleTerraformFile(t *testing.T) {
	result, err := parseTerraformFiles("test-fixtures/simple")
	if err != nil {
		t.Fatalf("Error parsing simple terraform files: %v", err)
	}

	// Should find resources
	if len(result.Resources) == 0 {
		t.Error("Expected to find resources, got 0")
	}

	// Check for specific resources
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

	// Should find many resources
	if len(result.Resources) < 10 {
		t.Errorf("Expected to find many resources, got %d", len(result.Resources))
	}

	// Check for VPC resources
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

	// Test specific resource type
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

	// Check for specific action
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

// Test helper function
func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()
	
	// Cleanup if needed
	os.Exit(code)
}

