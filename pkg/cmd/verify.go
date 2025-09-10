package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/cdxutil"
	"github.com/sbom-observer/observer-cli/pkg/files"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <sbom>",
	Short: "Verify an SBOM and optionally against artifacts",
	Long: `Verify that an SBOM is valid and optionally verify that all files in the artifacts directory
are included in the SBOM with matching hashes.

This command performs the following checks:
- Validates that the SBOM is a valid CycloneDX document
- If --artifacts is provided: ensures all files in the artifacts directory are present in the SBOM
- If --artifacts is provided: verifies that file hashes in the SBOM match the actual file hashes`,
	Args: cobra.ExactArgs(1),
	Run:  VerifyCommand,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().String("artifacts", "", "Directory containing artifacts to verify against the SBOM")
}

func VerifyCommand(cmd *cobra.Command, args []string) {
	sbomPath := args[0]
	artifactsDir, _ := cmd.Flags().GetString("artifacts")

	// Validate inputs
	if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
		log.Fatal("SBOM file does not exist", "path", sbomPath)
	}

	log.Printf("Verifying SBOM: %s", sbomPath)

	// Parse and validate SBOM
	bom, err := cdxutil.ParseCycloneDX(sbomPath)
	if err != nil {
		log.Fatal("Failed to parse SBOM", "error", err)
	}

	log.Printf("✓ SBOM is valid CycloneDX format")

	// Validate SBOM content structure
	validationErrors := validateSBOMContent(bom)
	if len(validationErrors) > 0 {
		log.Printf("✗ SBOM content validation failed:")
		for _, err := range validationErrors {
			log.Printf("  - %s", err)
		}
		os.Exit(1)
	}

	log.Printf("✓ SBOM content validation passed")

	// If no artifacts directory provided, just validate SBOM and exit
	if artifactsDir == "" {
		log.Printf("✓ SBOM validation completed successfully")
		os.Exit(0)
	}

	// Validate artifacts directory if provided
	if _, err := os.Stat(artifactsDir); os.IsNotExist(err) {
		log.Fatal("Artifacts directory does not exist", "path", artifactsDir)
	}

	log.Printf("Against artifacts: %s", artifactsDir)

	// Get all files in artifacts directory
	artifactFiles, err := getArtifactFiles(artifactsDir)
	if err != nil {
		log.Fatal("Failed to read artifacts directory", "error", err)
	}

	log.Printf("Found %d files in artifacts directory", len(artifactFiles))

	// Create a map of files and their hashes from the SBOM
	sbomFiles := make(map[string]string)

	// Check top-level components
	if bom.Components != nil {
		for _, component := range *bom.Components {
			if component.Type == cdx.ComponentTypeFile && component.Hashes != nil {
				// Extract filename from component name or BOMRef
				filename := component.Name
				if filename == "" {
					filename = component.BOMRef
				}

				// Find SHA-256 hash
				for _, hash := range *component.Hashes {
					if hash.Algorithm == "SHA-256" {
						sbomFiles[filename] = hash.Value
						break
					}
				}
			}
		}
	}

	// Check nested components under metadata.component
	if bom.Metadata != nil && bom.Metadata.Component != nil && bom.Metadata.Component.Components != nil {
		for _, component := range *bom.Metadata.Component.Components {
			if component.Type == cdx.ComponentTypeFile && component.Hashes != nil {
				// Extract filename from component name or BOMRef
				filename := component.Name
				if filename == "" {
					filename = component.BOMRef
				}

				// Find SHA-256 hash
				for _, hash := range *component.Hashes {
					if hash.Algorithm == "SHA-256" {
						sbomFiles[filename] = hash.Value
						break
					}
				}
			}
		}
	}

	log.Printf("Found %d file components in SBOM", len(sbomFiles))

	// Verify each artifact file
	allValid := true
	missingFiles := []string{}
	hashMismatches := []string{}

	for _, artifactFile := range artifactFiles {
		// Check if file exists in SBOM
		expectedHash, exists := sbomFiles[artifactFile]
		if !exists {
			missingFiles = append(missingFiles, artifactFile)
			allValid = false
			continue
		}

		// Calculate actual hash
		actualHash, err := files.HashFileSha256(filepath.Join(artifactsDir, artifactFile))
		if err != nil {
			log.Error("Failed to hash file", "file", artifactFile, "error", err)
			allValid = false
			continue
		}

		// Compare hashes
		if actualHash != expectedHash {
			hashMismatches = append(hashMismatches, fmt.Sprintf("%s (expected: %s, actual: %s)", artifactFile, expectedHash, actualHash))
			allValid = false
		} else {
			log.Printf("✓ %s", artifactFile)
		}
	}

	// Report results
	fmt.Println()
	if len(missingFiles) > 0 {
		log.Printf("✗ Files missing from SBOM:")
		for _, file := range missingFiles {
			log.Printf("  - %s", file)
		}
		fmt.Println()
	}

	if len(hashMismatches) > 0 {
		log.Printf("✗ Hash mismatches:")
		for _, mismatch := range hashMismatches {
			log.Printf("  - %s", mismatch)
		}
		fmt.Println()
	}

	if allValid {
		log.Printf("✓ All artifacts verified successfully")
		os.Exit(0)
	} else {
		log.Printf("✗ Verification failed")
		os.Exit(1)
	}
}

// getArtifactFiles recursively gets all files in the artifacts directory
func getArtifactFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			// Get relative path from artifacts directory
			relPath, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			// Normalize path separators for consistency
			relPath = strings.ReplaceAll(relPath, "\\", "/")
			files = append(files, relPath)
		}

		return nil
	})

	return files, err
}

// validateSBOMContent validates that the SBOM has essential structure and content
func validateSBOMContent(bom *cdx.BOM) []string {
	var errors []string

	// Check top level version
	if bom.Version == 0 {
		errors = append(errors, "missing top-level version field")
	}

	// Check top level metadata
	if bom.Metadata == nil {
		errors = append(errors, "missing top-level metadata")
	} else {
		// Check metadata.component with name and version
		if bom.Metadata.Component == nil {
			errors = append(errors, "missing metadata.component")
		} else {
			if bom.Metadata.Component.Name == "" {
				errors = append(errors, "missing metadata.component.name")
			}
			if bom.Metadata.Component.Version == "" {
				errors = append(errors, "missing metadata.component.version")
			}
		}
	}

	// Check at least one component in the top level component list
	if bom.Components == nil || len(*bom.Components) == 0 {
		errors = append(errors, "missing or empty top-level components list")
	}

	// Check at least one dependency
	if bom.Dependencies == nil || len(*bom.Dependencies) == 0 {
		errors = append(errors, "missing or empty dependencies list")
	}

	return errors
}
