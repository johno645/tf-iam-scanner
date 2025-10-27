package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	pathFlag              string
	outputFlag            string
	includeStateBackendFlag bool
	leastPrivilegeFlag    bool
	formatFlag            string
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
	rootCmd.Flags().BoolVar(&includeStateBackendFlag, "include-state-backend", false, "Include permissions for Terraform state backend operations")
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

	// Parse Terraform files
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
		if !includeStateBackendFlag {
			fmt.Fprintf(os.Stderr, "  Hint: Use --include-state-backend to add backend permissions\n")
		}
	}
	
	if leastPrivilegeFlag {
		services := extractServicesFromPolicy(policy)
		fmt.Fprintf(os.Stderr, "  Services requiring permissions: %s\n", strings.Join(services, ", "))
	}
}

func extractServicesFromPolicy(policy string) []string {
	services := make(map[string]bool)
	
	// Extract service names from the policy output
	lines := strings.Split(policy, "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") && !strings.Contains(line, "arn:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				service := strings.TrimSpace(parts[0])
				service = strings.Trim(service, "\"[],")
				services[service] = true
			}
		}
	}
	
	result := []string{}
	for service := range services {
		result = append(result, service)
	}
	sort.Strings(result)
	
	return result
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
