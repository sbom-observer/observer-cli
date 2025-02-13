package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sbom.observer/cli/pkg/cdxutil"
	"sbom.observer/cli/pkg/scanner"
	"text/template"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
	"sbom.observer/cli/pkg/client"
	"sbom.observer/cli/pkg/log"
)

// repoCmd represents the repo command
var repoCmd = &cobra.Command{
	Aliases: []string{"repository"},
	Use:     "repo",
	Short:   "Create an SBOM from a source repository",
	Long:    `Create an SBOM from a local source repository (or monorepo)`,
	Run:     RunRepoCommand,
	Args:    cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(repoCmd)

	// toggles
	repoCmd.Flags().BoolP("upload", "u", false, "Upload the results to https://sbom.observer")

	repoCmd.Flags().BoolP("recursive", "r", false, "Recursively scan subdirectories (short for --depth=1)")
	repoCmd.Flags().Uint("depth", 1, "Recursively scan subdirectories down to max tree depth (e.g. monorepos)")

	// output
	repoCmd.Flags().StringP("output", "o", "", "Output directory or file (merge) for the results (default: stdout)")
	repoCmd.Flags().BoolP("merge", "m", false, "Merge the results into a single BOM")
	//repoCmd.Flags().Bool("super", false, "Merge the results with a super BOM")
}

func RunRepoCommand(cmd *cobra.Command, args []string) {
	flagUpload, _ := cmd.Flags().GetBool("upload")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug
	flagDepth, _ := cmd.Flags().GetUint("depth")

	flagOutput, _ := cmd.Flags().GetString("output")
	flagMerge, _ := cmd.Flags().GetBool("merge")
	// TODO: load config from args[0]

	if len(args) != 1 {
		log.Fatal("the path to a source repository is required as an argument")
	}

	targets, err := scanner.FindScanTargets(args[0], flagDepth)
	if err != nil {
		log.Fatal("failed to find scan targets", "err", err)
	}

	if len(targets) == 0 {
		log.Infof("No targets found in %s", args[0])
		os.Exit(0)
	}

	// TODO: remove
	for _, target := range targets {
		log.Debugf("found target %s -> %v", target.Path, target.Files)
	}

	// scan targets
	for _, target := range targets {
		log.Infof("Generating SBOM for '%s'", target.Path)
		log.Debug("Generating SBOM", "path", target.Path, "target", target.Files)

		for _, scanner := range scanner.ScannersForTarget(*target) {
			log.Debug("running scanner", "id", scanner.Id())
			err = scanner.Scan(target)
			if err != nil {
				log.Fatal("failed to create SBOM for repository", "path", target.Path, "err", err)
			}
		}

		// fallback to directory name if no name is set
		if target.Config.Component.Name == "" {
			target.Config.Component.Name = filepath.Base(target.Path)
		}

		// merge results and add metadata
		log.Debugf("merging %d BOMs for target %s", len(target.Results), target.Path)

		target.Merged, err = cdxutil.DestructiveMergeSBOMs(target.Config, target.Results)
		if err != nil {
			log.Fatal("failed to merge SBOMs for target", "target", target.Path, "err", err)
		}

		log.Debugf("merged %d BOMs for target %s -> %s@%s", len(target.Results), target.Path, target.Merged.Metadata.Component.Name, target.Merged.Metadata.Component.Version)
	}

	// TODO: implement --merge flag (and --merge-with-ref or --super)

	if flagMerge {
		if len(targets) != 1 {
			log.Fatal("merge flag can only be used with a single target")
		}
	}

	// write to output
	if flagOutput != "" {
		if !isDirectory(flagOutput) && !flagMerge {
			log.Fatalf("output destination %s is not a directory. Did you mean --merge?", flagOutput)
		}

		for _, target := range targets {
			outputFilename := flagOutput

			if !flagMerge {
				outputTemplate := "sbom-{{.Name}}-{{.Module}}-{{.Timestamp}}.cdx.json"
				if target.Config.OutputTemplate != "" {
					outputTemplate = target.Config.OutputTemplate
				}

				outputFilename, err = generateFilename(outputTemplate, "", target.Merged.Metadata.Component)
				if err != nil {
					log.Fatal("failed to generate output filename", "err", err)
				}

				outputFilename, err = filepath.Abs(filepath.Join(flagOutput, outputFilename))
				if err != nil {
					log.Fatal("failed to get absolute path for output filename", "err", err)
				}
			}

			log.Debugf("writing SBOM to %s", outputFilename)

			out, err := os.Create(outputFilename)
			if err != nil {
				log.Fatal("failed to create output file", "filename", outputFilename, "err", err)
			}

			// use cdx provided encoder
			encoder := cdx.NewBOMEncoder(out, cdx.BOMFileFormatJSON)
			encoder.SetPretty(true)
			err = encoder.Encode(target.Merged)
			if err != nil {
				log.Fatal("failed to write output file", "filename", outputFilename, "err", err)
			}

			_ = out.Close()
		}
	}

	// upload
	if flagUpload {
		progress := log.NewProgressBar(int64(len(targets)), "Uploading BOMs", flagSilent)

		c := client.NewObserverClient()

		for _, target := range targets {
			outputTemplate := "sbom-{{.Name}}-{{.Module}}-{{.Timestamp}}.cdx.json"
			if target.Config.OutputTemplate != "" {
				outputTemplate = target.Config.OutputTemplate
			}

			outputFilename, err := generateFilename(outputTemplate, "", target.Merged.Metadata.Component)
			if err != nil {
				log.Fatal("failed to generate output filename", "err", err)
			}

			err = c.UploadSource(outputFilename, func(w io.Writer) error {
				encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
				encoder.SetPretty(true)
				return encoder.Encode(target.Merged)
			})
			if err != nil {
				log.Fatal("error when uploading", "file", outputFilename, "err", err)
			}

			_ = progress.Add(1)
		}

		_ = progress.Finish()
		_ = progress.Clear()

		log.Printf("Uploaded %d BOM(s)", len(targets))
	}

	// output to stdout
	if flagOutput == "" {
		for _, target := range targets {
			for _, result := range target.Results {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(result)
			}
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
