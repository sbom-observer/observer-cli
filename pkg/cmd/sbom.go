package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/mergex"
	"github.com/spf13/cobra"
)

// sbomCmd represents the sbom command
var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "SBOM utilities for CycloneDX Software Bill of Materials",
	Long:  `SBOM utilities for CycloneDX Software Bill of Materials including merging multiple BOMs`,
}

// mergeCmd represents the merge command
var mergeCmd = &cobra.Command{
	Use:   "merge [flags] bom1.json bom2.json [bom3.json...]",
	Short: "Merge two or more CycloneDX SBOM files into one",
	Long: `Merge two or more CycloneDX SBOM files into a single BOM using non-destructive merging.
The merge follows these rules:
- First input takes precedence for non-empty simple fields
- Array fields are combined with proper deduplication where applicable
- Entities with the same BOMRef are merged intelligently
- Original input files are never modified

Supported formats: JSON and XML (auto-detected by file extension)
Output format matches the first input file format unless overridden.`,
	Args: cobra.MinimumNArgs(2),
	Run:  runMerge,
}

func init() {
	rootCmd.AddCommand(sbomCmd)
	sbomCmd.AddCommand(mergeCmd)
	sbomCmd.AddCommand(diffCmd)

	mergeCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	mergeCmd.Flags().Bool("pretty", true, "Pretty print output")
}

func runMerge(cmd *cobra.Command, args []string) {
	outputPath, _ := cmd.Flags().GetString("output")
	prettyPrint, _ := cmd.Flags().GetBool("pretty")

	// Parse all input BOMs
	var boms []*cyclonedx.BOM
	var outputFormat cyclonedx.BOMFileFormat

	for i, filePath := range args {
		log.Debugf("Parsing BOM file: %s", filePath)

		bom, format, err := parseBOMFile(filePath)
		if err != nil {
			log.Fatalf("Failed to parse BOM file %s: %v", filePath, err)
		}

		// Use the format of the first file as the output format
		if i == 0 {
			outputFormat = format
		}

		boms = append(boms, bom)
	}

	if len(boms) == 0 {
		log.Fatal("No valid BOM files found")
	}

	log.Debugf("Merging %d BOM files", len(boms))

	// Perform the merge
	merged := boms[0]
	for i := 1; i < len(boms); i++ {
		log.Debugf("Merging BOM %d/%d", i+1, len(boms))
		merged = mergex.MergeBom(merged, boms[i])
	}

	log.Debugf("Merge completed successfully")

	// Write output
	if err := writeBOM(merged, outputPath, outputFormat, prettyPrint); err != nil {
		log.Fatalf("Failed to write merged BOM: %v", err)
	}

	if outputPath != "" {
		log.Printf("Merged BOM written to: %s", outputPath)
	}
}

func parseBOMFile(filePath string) (*cyclonedx.BOM, cyclonedx.BOMFileFormat, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, cyclonedx.BOMFileFormatJSON, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Detect format by file extension
	format := detectBOMFormat(filePath)

	// Create decoder and parse BOM
	decoder := cyclonedx.NewBOMDecoder(file, format)
	var bom cyclonedx.BOM
	if err := decoder.Decode(&bom); err != nil {
		return nil, format, fmt.Errorf("failed to decode BOM: %w", err)
	}

	return &bom, format, nil
}

func detectBOMFormat(filePath string) cyclonedx.BOMFileFormat {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".xml":
		return cyclonedx.BOMFileFormatXML
	case ".json":
		return cyclonedx.BOMFileFormatJSON
	default:
		// Default to JSON for unknown extensions
		log.Debugf("Unknown file extension %s, defaulting to JSON format", ext)
		return cyclonedx.BOMFileFormatJSON
	}
}

func writeBOM(bom *cyclonedx.BOM, outputPath string, format cyclonedx.BOMFileFormat, pretty bool) error {
	var writer *os.File
	var err error

	if outputPath == "" {
		writer = os.Stdout
	} else {
		writer, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer writer.Close()
	}

	// Create encoder
	encoder := cyclonedx.NewBOMEncoder(writer, format)

	if pretty {
		encoder.SetPretty(true)
	}

	// For JSON, disable HTML escaping to make the output more readable
	if format == cyclonedx.BOMFileFormatJSON {
		encoder.SetEscapeHTML(false)
	}

	// Encode BOM
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("failed to encode BOM: %w", err)
	}

	return nil
}
