package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Resource represents a Terraform resource or data source
type Resource struct {
	Type         string
	Name         string
	Provider     string
	Attributes   map[string]cty.Value
	ResourceType string // The actual AWS resource type for IAM
}

// BackendConfig represents Terraform backend configuration
type BackendConfig struct {
	Type   string
	Config map[string]string
}

// ParseResult contains all parsed information
type ParseResult struct {
	Resources     []Resource
	Backend       *BackendConfig
	DataSources   []Resource
}

// PermissionMap represents the permissions database
type PermissionMap map[string]ResourcePermissions

// ResourcePermissions defines actions and resource types for a resource
type ResourcePermissions struct {
	Actions       []string `json:"actions"`
	ResourceTypes []string `json:"resource_types"`
}

var permissionsDB PermissionMap

// loadPermissionsDB loads the permissions database from JSON
func loadPermissionsDB() error {
	data, err := os.ReadFile("permissions.json")
	if err != nil {
		return fmt.Errorf("error reading permissions.json: %w", err)
	}

	var db PermissionMap
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("error parsing permissions.json: %w", err)
	}

	permissionsDB = db
	return nil
}

// parseTerraformFiles scans a directory for .tf files and extracts resources
func parseTerraformFiles(dirPath string) (*ParseResult, error) {
	// Load permissions database
	if permissionsDB == nil {
		if err := loadPermissionsDB(); err != nil {
			return nil, err
		}
	}

	result := &ParseResult{
		Resources: []Resource{},
		DataSources: []Resource{},
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only process .tf files
		if strings.HasSuffix(info.Name(), ".tf") {
			fileResult, err := parseTerraformFile(path)
			if err != nil {
				return fmt.Errorf("error parsing %s: %w", path, err)
			}
			
			result.Resources = append(result.Resources, fileResult.Resources...)
			result.DataSources = append(result.DataSources, fileResult.DataSources...)
			
			if fileResult.Backend != nil && result.Backend == nil {
				result.Backend = fileResult.Backend
			}
		}

		// Check for terraform.tfstate files for backend detection
		if info.Name() == "terraform.tfstate" || strings.HasSuffix(info.Name(), ".tfstate") {
			backendInfo, err := extractBackendFromState(path)
			if err == nil && backendInfo != nil {
				result.Backend = backendInfo
			}
		}

		return nil
	})

	return result, err
}

// parseTerraformFile parses a single Terraform file using HCL v2
func parseTerraformFile(filePath string) (*ParseResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	result := &ParseResult{
		Resources: []Resource{},
		DataSources: []Resource{},
	}

	// Parse HCL
	file, diags := hclsyntax.ParseConfig(content, filePath, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		// Try to still extract what we can
		return extractWithSimpleParsing(content, filePath)
	}

	// Extract blocks from syntax body
	if syntaxBody, ok := file.Body.(*hclsyntax.Body); ok {
		for _, block := range syntaxBody.Blocks {
			switch block.Type {
			case "resource":
				resource := extractResourceFromBlock(block)
				if resource != nil {
					result.Resources = append(result.Resources, *resource)
				}
			case "data":
				dataSource := extractDataSourceFromBlock(block)
				if dataSource != nil {
					result.DataSources = append(result.DataSources, *dataSource)
				}
			case "terraform":
				backend := extractBackendFromBlock(block)
				if backend != nil {
					result.Backend = backend
				}
			}
		}
	}

	return result, nil
}

// extractResourceFromBlock extracts resource information from an HCL block
func extractResourceFromBlock(block *hclsyntax.Block) *Resource {
	if len(block.Labels) < 2 {
		return nil
	}

	fullType := block.Labels[0]
	name := block.Labels[1]

	// Extract provider
	provider := "aws"
	
	if strings.HasPrefix(fullType, "aws_") {
		provider = "aws"
	} else if strings.Contains(fullType, "_") {
		parts := strings.SplitN(fullType, "_", 2)
		provider = parts[0]
	}

	// Extract attributes
	attributes := make(map[string]cty.Value)
	if block.Body != nil {
		for name, attr := range block.Body.Attributes {
			val, _ := attr.Expr.Value(nil)
			attributes[name] = val
		}
	}

	return &Resource{
		Type:       fullType,
		Name:       name,
		Provider:   provider,
		Attributes: attributes,
		ResourceType: fullType,
	}
}

// extractDataSourceFromBlock extracts data source information from an HCL block
func extractDataSourceFromBlock(block *hclsyntax.Block) *Resource {
	if len(block.Labels) < 2 {
		return nil
	}

	fullType := block.Labels[0]
	name := block.Labels[1]

	provider := "aws"
	
	if strings.HasPrefix(fullType, "aws_") {
		provider = "aws"
	}

	return &Resource{
		Type:         fullType,
		Name:         name,
		Provider:     provider,
		ResourceType: fullType,
	}
}

func extractBackendFromBlock(block *hclsyntax.Block) *BackendConfig {
	for _, nestedBlock := range block.Body.Blocks {
		if nestedBlock.Type == "backend" && len(nestedBlock.Labels) > 0 {
			config := make(map[string]string)
			
			for name, attr := range nestedBlock.Body.Attributes {
				val, _ := attr.Expr.Value(nil)
				if val.Type() == cty.String {
					config[name] = val.AsString()
				}
			}
			
			return &BackendConfig{
				Type:   nestedBlock.Labels[0],
				Config: config,
			}
		}
	}
	
	return nil
}

// extractBackendFromState attempts to extract backend info from state file
func extractBackendFromState(filePath string) (*BackendConfig, error) {
	// This is a simplified extractor - full implementation would parse JSON properly
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	contentStr := string(content)
	if strings.Contains(contentStr, "s3") || strings.Contains(contentStr, "backend") {
		return &BackendConfig{
			Type:   "s3",
			Config: map[string]string{},
		}, nil
	}

	return nil, nil
}

// extractWithSimpleParsing is a fallback parser when HCL parsing fails
func extractWithSimpleParsing(content []byte, filePath string) (*ParseResult, error) {
	result := &ParseResult{
		Resources: []Resource{},
		DataSources: []Resource{},
	}

	lines := strings.Split(string(content), "\n")
	var currentBlock string
	var currentName string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}

		// Check for resource/data blocks
		if strings.HasPrefix(trimmed, "resource \"") {
			currentBlock = "resource"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				resourceType := strings.Trim(parts[1], "\"")
				if len(parts) >= 3 {
					currentName = strings.Trim(parts[2], "\"")
				}

				provider := "aws"
				if strings.HasPrefix(resourceType, "aws_") {
					provider = "aws"
				}

				result.Resources = append(result.Resources, Resource{
					Type:         resourceType,
					Name:         currentName,
					Provider:     provider,
					ResourceType: resourceType,
				})
			}
		} else if strings.HasPrefix(trimmed, "data \"") {
			currentBlock = "data"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				resourceType := strings.Trim(parts[1], "\"")
				if len(parts) >= 3 {
					currentName = strings.Trim(parts[2], "\"")
				}

				provider := "aws"
				if strings.HasPrefix(resourceType, "aws_") {
					provider = "aws"
				}

				result.DataSources = append(result.DataSources, Resource{
					Type:         resourceType,
					Name:         currentName,
					Provider:     provider,
					ResourceType: resourceType,
				})
			}
		}

		// Check for backend configuration
		if strings.Contains(trimmed, "backend \"") && currentBlock == "terraform" {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				backendType := strings.Trim(parts[1], "\"")
				result.Backend = &BackendConfig{
					Type:   backendType,
					Config: make(map[string]string),
				}
			}
		}

		// Track terraform blocks for backend detection
		if strings.HasPrefix(trimmed, "terraform") {
			currentBlock = "terraform"
		}

		// Reset when block ends
		if trimmed == "}" {
			currentBlock = ""
			currentName = ""
		}
	}

	return result, nil
}

// getRequiredPermissions returns the required IAM actions for a resource type
func getRequiredPermissions(resourceType string) []string {
	if permissionsDB == nil {
		return []string{}
	}

	if perms, exists := permissionsDB[resourceType]; exists {
		return perms.Actions
	}

	return []string{}
}
