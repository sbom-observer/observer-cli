package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/build-observer/pkg/traceopens"
	"github.com/spf13/cobra"
	"sbom.observer/cli/pkg/builds"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/types"
)

// buildCmd represents the diff command
var buildCmd = &cobra.Command{
	Use:     "build",
	Short:   "Observe a build process and optionally generate a CycloneDX SBOM",
	Long:    "Observe and record files opened and executed during a build process and optionally generate a CycloneDX SBOM",
	Example: `sudo observer build -u ci -- make`,
	Run:     RunBuildCommand,
	Args:    cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(buildCmd)

	buildCmd.Flags().StringP("output", "o", "build-observations.json", "Output filename for build observations")
	buildCmd.Flags().StringP("sbom", "b", "", "Output filename for CycloneDX SBOM")
	buildCmd.Flags().StringP("user", "u", "", "Run command as user")
	buildCmd.Flags().StringP("config", "c", "", "Config file (i.e. observer.yaml)")
	buildCmd.Flags().StringSliceP("exclude", "e", []string{".", "..", "*.so", "*.so.6", "*.so.2", "*.a", "/etc/ld.so.cache"}, "Exclude files from output")
}

func RunBuildCommand(cmd *cobra.Command, args []string) {
	log.Debugf("Running build command args=%v", args)

	if syscall.Getuid() != 0 {
		fmt.Println("build-observer currently only supports running as the root user. Please run with sudo.")
		os.Exit(1)
	}

	if len(args) == 0 {
		fmt.Println("Please provide a command to trace as an argument (i.e. build-observer -u ci '/usr/bin/make').")
		os.Exit(1)
	}

	user, _ := cmd.Flags().GetString("user")
	result, err := traceopens.TraceCommand(args, user)
	if err != nil {
		fmt.Printf("Error tracing command: %s\n", err)
		os.Exit(1)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current working directory: %s\n", err)
		os.Exit(1)
	}

	buildObservations := builds.BuildObservations{
		Start:            result.Start,
		Stop:             result.Stop,
		FilesOpened:      result.FilesOpened,
		FilesExecuted:    result.FilesExecuted,
		WorkingDirectory: cwd,
	}

	// sort filesOpened and filesExecuted
	sort.Strings(buildObservations.FilesOpened)
	sort.Strings(buildObservations.FilesExecuted)

	// load config file if provided
	var config types.ScanConfig
	configFilename, _ := cmd.Flags().GetString("config")
	if configFilename != "" {
		err := types.LoadConfig(&config, configFilename)
		if err != nil {
			log.Fatalf("failed to load config file: %v", err)
		}
		log.Debugf("loaded config from %s", configFilename)
	}

	// TODO: 2025-02-24 - add build.exclude to config
	// filter out files that match the exclude pattern
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	for _, pattern := range exclude {
		buildObservations.FilesOpened = types.Filter(buildObservations.FilesOpened, func(s string) bool {
			if strings.HasPrefix(pattern, "*") {
				return !strings.HasSuffix(s, pattern[1:])
			}
			return s != pattern
		})
		buildObservations.FilesExecuted = types.Filter(buildObservations.FilesExecuted, func(s string) bool {
			if strings.HasPrefix(pattern, "*") {
				return !strings.HasSuffix(s, pattern[1:])
			}
			return s != pattern
		})
	}

	// write result to output file as json
	output := cmd.Flag("output").Value.String()
	out, err := os.Create(output)
	if err != nil {
		fmt.Printf("Error creating output file: %s\n", err)
		os.Exit(1)
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.Encode(buildObservations)
	fmt.Printf("Wrote build observations to %s\n", output)

	// generate CycloneDX BOM if requested
	if sbomFilename, _ := cmd.Flags().GetString("sbom"); sbomFilename != "" {
		log.Debugf("filtering dependencies from %d/%d observed build operations", len(buildObservations.FilesOpened), len(buildObservations.FilesExecuted))
		buildObservations = builds.DependencyObservations(buildObservations)

		dependencies, err := builds.ResolveDependencies(buildObservations)
		if err != nil {
			log.Fatalf("failed to parse build observations file: %v", err)
		}

		log.Debugf("resolved %d unique code dependencies", len(dependencies.Code))
		log.Debugf("resolved %d unique tool dependencies", len(dependencies.Tools))
		log.Debugf("resolved %d unique transitive dependencies", len(dependencies.Transitive))

		bom, err := builds.GenerateCycloneDX(dependencies, config)
		if err != nil {
			log.Fatalf("failed to generate CycloneDX BOM: %v", err)
		}

		// write bom to output file as json
		log.Debugf("writing SBOM to %s", sbomFilename)

		out, err := os.Create(sbomFilename)
		if err != nil {
			log.Fatal("failed to create output file", "filename", sbomFilename, "err", err)
		}

		// use cdx provided encoder
		encoder := cdx.NewBOMEncoder(out, cdx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		err = encoder.Encode(bom)
		if err != nil {
			log.Fatal("failed to write output file", "filename", sbomFilename, "err", err)
		}

		_ = out.Close()
	}
}
