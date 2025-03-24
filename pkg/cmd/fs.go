package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"sbom.observer/cli/pkg/cdxutil"
	"sbom.observer/cli/pkg/scanner"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
	"sbom.observer/cli/pkg/client"
	"sbom.observer/cli/pkg/log"
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

	// output
	filesystemCmd.Flags().StringP("output", "o", "", "Output directory for the results (default: stdout)")
	filesystemCmd.Flags().StringP("merge", "m", "", "Merge (filename) the results into a single BOM")
	//repoCmd.Flags().Bool("super", false, "Merge the results with a super BOM")
}

func RunFilesystemCommand(cmd *cobra.Command, args []string) {
	var err error

	flagUpload, _ := cmd.Flags().GetBool("upload")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug
	flagDepth, _ := cmd.Flags().GetUint("depth")

	flagOutput, _ := cmd.Flags().GetString("output")
	flagMerge, _ := cmd.Flags().GetString("merge")
	// TODO: load config from args[0]

	if len(args) < 1 {
		log.Fatal("the path to a source repository is required as an argument")
	}

	// find targets
	var targets []*scanner.ScanTarget
	{
		pathToTarget := map[string]*scanner.ScanTarget{}
		for _, arg := range args {
			log.Debugf("finding scan targets for %s", arg)
			ts, err := scanner.FindScanTargets(arg, flagDepth)
			if err != nil {
				log.Fatal("failed to find scan targets", "err", err)
			}

			if len(ts) == 0 {
				log.Debugf("No targets found in %s", arg)
				continue
			}

			for path, target := range ts {
				if existingTarget, ok := pathToTarget[path]; ok {
					for file, ecosystem := range existingTarget.Files {
						target.Files[file] = ecosystem
					}
				}

				pathToTarget[path] = target
			}
		}

		for _, target := range pathToTarget {
			targets = append(targets, target)
		}

		// sort targets to make scanning is deterministic
		sort.Slice(targets, func(i, j int) bool {
			return len(targets[i].Path) < len(targets[j].Path)
		})
	}

	// TODO: remove
	for _, target := range targets {
		log.Debugf("found target %s -> %v", target.Path, target.Files)
	}

	if len(targets) == 0 {
		log.Fatal("no targets found")
	}

	// scan targets
	for _, target := range targets {
		log.Infof("Generating SBOM for '%s'", target.Path)
		log.Debug("Generating SBOM", "path", target.Path, "target", target.Files)

		for _, scanner := range scanner.ScannersForTarget(*target) {
			log.Debug("running scanner", "id", scanner.Id())
			err := scanner.Scan(target)
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

	// merge to single file
	if flagMerge != "" {
		if isDirectory(flagMerge) {
			log.Fatalf("output destination %s is a directory. Did you mean --output?", flagMerge)
		}

		// TODO: remove
		// if len(targets) != 1 {
		// 	log.Fatal("merge flag can only be used with a single target")
		// }

		// var merged *cdx.BOM
		// for _, target := range targets {
		// 	merged = target.Merged
		// }

		var rootPath string
		var targetsToMerge []*scanner.ScanTarget

		for _, target := range targets {
			if rootPath == "" || len(target.Path) < len(rootPath) {
				rootPath = target.Path
			} else if !strings.HasPrefix(target.Path, rootPath) {
				log.Fatal("targets are not part of the same root path", "root", rootPath, "target", target.Path)
			}
			targetsToMerge = append(targetsToMerge, target)
		}

		// sort targets by path length
		sort.Slice(targetsToMerge, func(i, j int) bool {
			return len(targetsToMerge[i].Path) < len(targetsToMerge[j].Path)
		})

		var boms []*cdx.BOM
		for _, target := range targetsToMerge {
			boms = append(boms, target.Merged)
		}

		// TODO: replace with an additive merge
		merged, err := cdxutil.DestructiveMergeSBOMs(targetsToMerge[0].Config, boms)
		if err != nil {
			log.Fatal("failed to merge SBOMs for config", "config", targetsToMerge[0].Merged.Metadata.Component.Name, "err", err)
		}

		log.Debugf("merged %d BOMs to %s %s", len(boms), merged.Metadata.Component.Name, merged.Metadata.Component.Version)

		outputFilename := flagMerge

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

	// write to output
	if flagOutput != "" {
		if !isDirectory(flagOutput) {
			log.Fatalf("output destination %s is not a directory. Did you mean --merge?", flagOutput)
		}

		for _, target := range targets {

			outputTemplate := "sbom-{{.Name}}-{{.Module}}-{{.Timestamp}}.cdx.json"
			if target.Config.OutputTemplate != "" {
				outputTemplate = target.Config.OutputTemplate
			}

			outputFilename, err := generateFilename(outputTemplate, "", target.Merged.Metadata.Component)
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
			err = encoder.Encode(target.Merged)
			if err != nil {
				log.Fatal("failed to write output file", "filename", outputFilename, "err", err)
			}

			_ = out.Close()
		}
	}

	// upload
	// TODO: handle upload merged
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
	if flagOutput == "" && flagMerge == "" {
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
