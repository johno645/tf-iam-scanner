package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

//go:embed permissions.json
var embeddedPermissionsDB []byte

//go:generate go run cmd/generate-permissions/main.go

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
	Resources   []Resource
	Backend     *BackendConfig
	DataSources []Resource
	Modules     []string // local module source paths found during parsing
	Warnings    []string // non-fatal issues encountered during parsing
}

// PermissionMap represents the permissions database
type PermissionMap map[string]ResourcePermissions

// ResourcePermissions defines actions and resource types for a resource
type ResourcePermissions struct {
	Actions       []string `json:"actions"`
	ResourceTypes []string `json:"resource_types"`
}

var permissionsDB PermissionMap

// loadPermissionsDB loads the permissions database from the embedded JSON
func loadPermissionsDB() error {
	var db PermissionMap
	if err := json.Unmarshal(embeddedPermissionsDB, &db); err != nil {
		return fmt.Errorf("error parsing permissions.json: %w", err)
	}

	permissionsDB = db
	return nil
}

// parseTerraformFiles scans a directory for .tf files and extracts resources.
// It also follows local module sources recursively.
func parseTerraformFiles(dirPath string) (*ParseResult, error) {
	// Load permissions database
	if permissionsDB == nil {
		if err := loadPermissionsDB(); err != nil {
			return nil, err
		}
	}

	result := &ParseResult{
		Resources:   []Resource{},
		DataSources: []Resource{},
	}

	// Track visited directories to avoid re-scanning modules
	visited := make(map[string]bool)
	scanDir(dirPath, result, visited)

	return result, nil
}

// scanDir recursively scans a directory and follows local module sources.
func scanDir(dirPath string, result *ParseResult, visited map[string]bool) {
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Could not resolve path %s: %v", dirPath, err))
		return
	}

	cleanPath := filepath.Clean(absPath)
	if visited[cleanPath] {
		return
	}
	visited[cleanPath] = true

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Error accessing %s: %v", path, err))
			return nil
		}

		// Only process .tf files (skip .terraform directory)
		if strings.HasSuffix(info.Name(), ".tf") && !strings.Contains(path, "/.terraform/") {
			fileResult, fileErr := parseTerraformFile(path)
			if fileErr != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Error parsing %s: %v", path, fileErr))
				return nil
			}

			result.Resources = append(result.Resources, fileResult.Resources...)
			result.DataSources = append(result.DataSources, fileResult.DataSources...)
			result.Modules = append(result.Modules, fileResult.Modules...)

			if fileResult.Backend != nil && result.Backend == nil {
				result.Backend = fileResult.Backend
			}
		}

		// Check for terraform.tfstate files for backend detection
		if info.Name() == "terraform.tfstate" || strings.HasSuffix(info.Name(), ".tfstate") {
			backendInfo, backendErr := extractBackendFromState(path)
			if backendErr == nil && backendInfo != nil {
				result.Backend = backendInfo
			}
		}

		return nil
	})

	// Follow local module sources found in this directory
	for _, moduleSource := range result.Modules {
		if isLocalModuleSource(moduleSource) {
			modulePath := filepath.Join(dirPath, moduleSource)
			scanDir(modulePath, result, visited)
		}
	}
}

// isLocalModuleSource returns true if the module source is a local path.
func isLocalModuleSource(source string) bool {
	return strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") ||
		(strings.HasPrefix(source, "/") && !strings.Contains(source, "//"))
}

// parseTerraformFile parses a single Terraform file using HCL v2
func parseTerraformFile(filePath string) (*ParseResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	result := &ParseResult{
		Resources:   []Resource{},
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
			case "module":
				source := extractModuleSource(block)
				if source != "" {
					result.Modules = append(result.Modules, source)
				}
			}
		}
	}

	return result, nil
}

// extractModuleSource extracts the source attribute from a module block.
func extractModuleSource(block *hclsyntax.Block) string {
	if block.Body == nil {
		return ""
	}
	for name, attr := range block.Body.Attributes {
		if name == "source" {
			val, _ := attr.Expr.Value(nil)
			if val.Type() == cty.String {
				return val.AsString()
			}
		}
	}
	return ""
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
		Type:         fullType,
		Name:         name,
		Provider:     provider,
		Attributes:   attributes,
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
		Resources:   []Resource{},
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
		} else if strings.HasPrefix(trimmed, "module \"") {
			currentBlock = "module"
			// Simple source extraction from module block
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentName = strings.Trim(parts[1], "\"")
			}
		}

		// Check for module source attribute
		if currentBlock == "module" && strings.Contains(trimmed, "source") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				source := strings.TrimSpace(parts[1])
				source = strings.Trim(source, "\"")
				if isLocalModuleSource(source) {
					result.Modules = append(result.Modules, source)
				}
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

// --- Terraform Plan JSON parsing ---

// planFile represents the top-level structure of a terraform show -json output.
type planFile struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	PlannedValues    *planState       `json:"planned_values"`
	ResourceChanges  []planResourceChange `json:"resource_changes"`
	Configuration    *planConfig      `json:"configuration"`
}

type planState struct {
	RootModule planModule `json:"root_module"`
}

type planModule struct {
	Resources    []planResource      `json:"resources"`
	ChildModules []planChildModule   `json:"child_modules"`
}

type planChildModule struct {
	Address   string         `json:"address"`
	Resources []planResource `json:"resources"`
}

type planResource struct {
	Address      string `json:"address"`
	Mode         string `json:"mode"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
}

type planResourceChange struct {
	Address      string             `json:"address"`
	Mode         string             `json:"mode"`
	Type         string             `json:"type"`
	Name         string             `json:"name"`
	ProviderName string             `json:"provider_name"`
	Change       planChangeDetail   `json:"change"`
}

type planChangeDetail struct {
	Actions []string `json:"actions"`
}

type planConfig struct {
	RootModule planConfigModule `json:"root_module"`
}

type planConfigModule struct {
	Resources   []planResource            `json:"resources"`
	ModuleCalls map[string]planModuleCall `json:"module_calls"`
}

type planModuleCall struct {
	Source string `json:"source"`
}

// parsePlanFile reads a terraform show -json plan file and extracts resources,
// data sources, and module sources.
func parsePlanFile(filePath string) (*ParseResult, error) {
	// Load permissions database
	if permissionsDB == nil {
		if err := loadPermissionsDB(); err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading plan file: %w", err)
	}

	var plan planFile
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("error parsing plan JSON: %w", err)
	}

	result := &ParseResult{
		Resources:   []Resource{},
		DataSources: []Resource{},
	}

	// Extract from resource_changes — this is the authoritative list with
	// the planned actions for each resource.
	for _, rc := range plan.ResourceChanges {
		if !strings.HasPrefix(rc.ProviderName, "registry.terraform.io/hashicorp/aws") &&
			!strings.HasPrefix(rc.Type, "aws_") {
			continue
		}

		resource := Resource{
			Type:         rc.Type,
			Name:         rc.Name,
			Provider:     "aws",
			ResourceType: rc.Type,
		}

		if rc.Mode == "data" {
			result.DataSources = append(result.DataSources, resource)
		} else {
			result.Resources = append(result.Resources, resource)
		}
	}

	// Extract module sources from configuration
	if plan.Configuration != nil {
		extractPlanModules(&plan, result)
	}

	return result, nil
}

// extractPlanModules extracts module source paths from the plan configuration.
func extractPlanModules(plan *planFile, result *ParseResult) {
	if plan.Configuration == nil {
		return
	}
	for _, call := range plan.Configuration.RootModule.ModuleCalls {
		if isLocalModuleSource(call.Source) {
			result.Modules = append(result.Modules, call.Source)
		}
	}
}
