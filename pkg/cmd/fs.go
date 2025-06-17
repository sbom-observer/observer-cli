package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sbom-observer/observer-cli/pkg/tasks"
	"os"
	"path/filepath"
	"regexp"
	"text/template"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/spf13/cobra"
)

// filesystemCmd represents the repo command
var filesystemCmd = &cobra.Command{
	Aliases: []string{"filesystem", "repo"},
	Use:     "fs",
	Short:   "Create an SBOM from a filesystem directory (source repository, including monorepos) or list of files",
	Long:    "Create an SBOM from a filesystem directory (source repository, including monorepos) or list of files",
	Run:     RunFilesystemCommand,
	Args:    cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(filesystemCmd)

	// toggles
	filesystemCmd.Flags().BoolP("upload", "u", false, "Upload the results to https://sbom.observer")

	filesystemCmd.Flags().BoolP("recursive", "r", false, "Recursively scan subdirectories (short for --depth=1)")
	filesystemCmd.Flags().Uint("depth", 1, "Recursively scan subdirectories down to max tree depth (e.g. monorepos)")

	// artifacts
	filesystemCmd.Flags().StringArrayP("artifacts", "a", []string{}, "Artifacts that makes up the software described by the SBOM")

	// paths
	filesystemCmd.Flags().StringArrayP("vendor", "v", []string{}, "Include vendor path (e.g. ./vendor etc) in the scan. This is useful for monorepos or projects with vendored dependencies.")

	// output
	filesystemCmd.Flags().StringP("output", "o", "", "Output filename or directory for the results (default: stdout)")
	filesystemCmd.Flags().BoolP("merge", "m", true, "Merge the results into a single BOM")
	//repoCmd.Flags().Bool("super", false, "Merge the results with a super BOM")
}

func RunFilesystemCommand(cmd *cobra.Command, args []string) {
	flagUpload, _ := cmd.Flags().GetBool("upload")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug
	flagDepth, _ := cmd.Flags().GetUint("depth")

	flagOutput, _ := cmd.Flags().GetString("output")
	flagMerge, _ := cmd.Flags().GetBool("merge")
	flagArtifacts, _ := cmd.Flags().GetStringArray("artifacts")
	flagVendorPaths, _ := cmd.Flags().GetStringArray("vendor")
	// TODO: load config from args[0]

	RunFilesystemScanner(args, flagVendorPaths, flagDepth, flagOutput, flagMerge, flagArtifacts, flagUpload, flagSilent)
}

func RunFilesystemScanner(paths []string, vendorPaths []string, flagDepth uint, flagOutput string, flagMerge bool, flagArtifacts []string, flagUpload bool, flagSilent bool) {
	if len(paths) < 1 {
		log.Fatal("the path to a source repository is required as an argument")
	}

	results, err := tasks.CreateFilesystemSBOM(paths, vendorPaths, flagDepth, flagMerge, flagArtifacts)
	if err != nil {
		log.Fatal("failed to create filesystem SBOM", "err", err)
	}

	// write to output
	if flagOutput != "" {
		if len(results) == 1 {

			// output merged BOM
			outputFilename := flagOutput

			log.Debugf("writing SBOM to %s", outputFilename)

			out, err := os.Create(flagOutput)
			if err != nil {
				log.Fatal("failed to create output file", "filename", outputFilename, "err", err)
			}

			// use cdx provided encoder
			encoder := cdx.NewBOMEncoder(out, cdx.BOMFileFormatJSON)
			encoder.SetPretty(true)
			err = encoder.Encode(results[0])
			if err != nil {
				log.Fatal("failed to write output file", "filename", outputFilename, "err", err)
			}

			_ = out.Close()

		}

		if len(results) > 1 {
			if !isDirectory(flagOutput) {
				log.Fatalf("output destination %s is not a directory. Did you mean --merge?", flagOutput)
			}

			for _, merged := range results {

				outputTemplate := "sbom-{{.Name}}-{{.Module}}-{{.Timestamp}}.cdx.json"
				// if target.Config.OutputTemplate != "" {
				// outputTemplate = target.Config.OutputTemplate
				// }

				outputFilename, err := generateFilename(outputTemplate, "", merged.Metadata.Component)
				if err != nil {
					log.Fatal("failed to generate output filename", "err", err)
				}

				outputFilename, err = filepath.Abs(filepath.Join(flagOutput, outputFilename))
				if err != nil {
					log.Fatal("failed to get absolute path for output filename", "err", err)
				}

				log.Debugf("writing SBOM to %s", outputFilename)

				out, err := os.Create(outputFilename)
				if err != nil {
					log.Fatal("failed to create output file", "filename", outputFilename, "err", err)
				}

				// use cdx provided encoder
				encoder := cdx.NewBOMEncoder(out, cdx.BOMFileFormatJSON)
				encoder.SetPretty(true)
				err = encoder.Encode(merged)
				if err != nil {
					log.Fatal("failed to write output file", "filename", outputFilename, "err", err)
				}

				_ = out.Close()
			}
		}
	}

	// upload
	// TODO: handle upload merged
	// if flagUpload {
	// 	progress := log.NewProgressBar(int64(len(targets)), "Uploading BOMs", flagSilent)

	// 	c := client.NewObserverClient()

	// 	for _, target := range targets {
	// 		outputTemplate := "sbom-{{.Name}}-{{.Module}}-{{.Timestamp}}.cdx.json"
	// 		if target.Config.OutputTemplate != "" {
	// 			outputTemplate = target.Config.OutputTemplate
	// 		}

	// 		outputFilename, err := generateFilename(outputTemplate, "", target.Merged.Metadata.Component)
	// 		if err != nil {
	// 			log.Fatal("failed to generate output filename", "err", err)
	// 		}

	// 		err = c.UploadSource(outputFilename, func(w io.Writer) error {
	// 			encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	// 			encoder.SetPretty(true)
	// 			return encoder.Encode(target.Merged)
	// 		})
	// 		if err != nil {
	// 			log.Fatal("error when uploading", "file", outputFilename, "err", err)
	// 		}

	// 		_ = progress.Add(1)
	// 	}

	// 	_ = progress.Finish()
	// 	_ = progress.Clear()

	// 	log.Printf("Uploaded %d BOM(s)", len(targets))
	// }

	// output to stdout
	if flagOutput == "" {
		for _, merged := range results {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(merged)
		}
	}
}

func generateFilename(templateString string, module string, component *cdx.Component) (string, error) {
	t, err := template.New("filename").Parse(templateString)
	if err != nil {
		return "", fmt.Errorf("failed to parse filename template: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")

	var buf bytes.Buffer
	err = t.Execute(&buf, struct {
		Module    string
		Timestamp string
		Name      string
		Version   string
		Group     string
	}{
		Module:    module,
		Timestamp: timestamp,
		Name:      component.Name,
		Version:   component.Version,
		Group:     component.Group,
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute filename template: %w", err)
	}

	filename := buf.String()
	filename = regexp.MustCompile("-+").ReplaceAllString(filename, "-")

	return filename, nil
}

func isDirectory(filename string) bool {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		// If there's an error (e.g., file does not exist), return false
		return false
	}
	// Check if the FileMode is a directory
	return fileInfo.IsDir()
}
