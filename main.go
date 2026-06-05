package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	pathFlag               string
	outputFlag             string
	includeStateBackendFlag bool
	leastPrivilegeFlag     bool
	formatFlag             string
)

var rootCmd = &cobra.Command{
	Use:   "tf-iam-scanner",
	Short: "Scan Terraform files and generate minimum IAM policies",
	Long: `A tool that scans Terraform files, extracts AWS resources and data sources,
and generates the minimum IAM policy JSON required for those resources.

This tool uses proper HCL parsing to extract resources and generates IAM policies
with different output formats and granularity options.`,
	Run: runScanner,
}

func init() {
	rootCmd.Flags().StringVarP(&pathFlag, "path", "p", ".", "Path to directory containing Terraform files")
	rootCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output file path for the IAM policy (default: stdout)")
	rootCmd.Flags().BoolVar(&includeStateBackendFlag, "include-state-backend", true, "Include permissions for Terraform state backend operations (use --include-state-backend=false to exclude)")
	rootCmd.Flags().BoolVar(&leastPrivilegeFlag, "least-privilege", false, "Generate separate statements per service with specific resource ARNs")
	rootCmd.Flags().StringVarP(&formatFlag, "format", "f", "json", "Output format (json, yaml, terraform)")
}

func runScanner(cmd *cobra.Command, args []string) {
	// Validate path
	if pathFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: path is required\n")
		os.Exit(1)
	}

	// Validate format
	validFormats := map[string]bool{"json": true, "yaml": true, "terraform": true}
	if !validFormats[formatFlag] {
		fmt.Fprintf(os.Stderr, "Error: invalid format %s. Valid formats: json, yaml, terraform\n", formatFlag)
		os.Exit(1)
	}

	// Parse format
	format := OutputFormat(formatFlag)

	// Parse Terraform files (with module resolution)
	result, err := parseTerraformFiles(pathFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing Terraform files: %v\n", err)
		os.Exit(1)
	}

	if len(result.Resources) == 0 && len(result.DataSources) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: No AWS resources or data sources found in %s\n", pathFlag)
	}

	// Generate IAM policy
	policy, err := generateIAMPolicy(result, includeStateBackendFlag, format, leastPrivilegeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating IAM policy: %v\n", err)
		os.Exit(1)
	}

	// Output policy
	if outputFlag != "" {
		err := os.WriteFile(outputFlag, []byte(policy), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("IAM policy written to: %s\n", outputFlag)
	} else {
		fmt.Println(policy)
	}

	// Print summary
	fmt.Fprintf(os.Stderr, "\nSummary:\n")
	fmt.Fprintf(os.Stderr, "  Resources found: %d\n", len(result.Resources))
	fmt.Fprintf(os.Stderr, "  Data sources found: %d\n", len(result.DataSources))

	if result.Backend != nil {
		fmt.Fprintf(os.Stderr, "  Backend detected: %s\n", result.Backend.Type)
		if includeStateBackendFlag {
			fmt.Fprintf(os.Stderr, "  State backend permissions: included\n")
		} else {
			fmt.Fprintf(os.Stderr, "  State backend permissions: excluded (use --include-state-backend to include)\n")
		}
	}

	if leastPrivilegeFlag {
		services := extractServicesFromResult(result, includeStateBackendFlag)
		fmt.Fprintf(os.Stderr, "  Services requiring permissions: %s\n", strings.Join(services, ", "))
	}
}

// extractServicesFromResult extracts distinct AWS service names from the parsed result.
func extractServicesFromResult(result *ParseResult, includeBackend bool) []string {
	services := make(map[string]bool)

	for _, resource := range result.Resources {
		if resource.Provider == "aws" {
			perms := getRequiredPermissions(resource.Type)
			for _, action := range perms {
				parts := strings.Split(action, ":")
				if len(parts) == 2 {
					services[parts[0]] = true
				}
			}
		}
	}

	for _, ds := range result.DataSources {
		if ds.Provider == "aws" {
			dataSourceKey := "data." + ds.Type
			perms := getRequiredPermissions(dataSourceKey)
			if len(perms) == 0 {
				perms = getRequiredPermissions(ds.Type)
			}
			for _, action := range perms {
				if isReadOnlyAction(action) {
					parts := strings.Split(action, ":")
					if len(parts) == 2 {
						services[parts[0]] = true
					}
				}
			}
		}
	}

	if includeBackend {
		services["s3"] = true
		services["dynamodb"] = true
	}
	services["sts"] = true

	serviceList := make([]string, 0, len(services))
	for service := range services {
		serviceList = append(serviceList, service)
	}
	sort.Strings(serviceList)

	return serviceList
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
