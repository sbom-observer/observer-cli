package cmd

import (
	"os"

	"github.com/sbom-observer/observer-cli/pkg/client"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/spf13/cobra"
)

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Aliases: []string{"up"},
	Use:     "upload <sbom>...",
	Short:   "Upload one or more attestations (SBOMs) to https://sbom.observer",
	Long:    `Upload one or more attestations (SBOMs) to https://sbom.observer`,
	Run:     UploadCommand,
}

func init() {
	rootCmd.AddCommand(uploadCmd)

	uploadCmd.Flags().StringP("retention-policy", "p", "", "Retention policy for the uploaded SBOM")
	uploadCmd.Flags().StringP("retention-keep", "n", "1", "Retain N versions of the SBOM")
	uploadCmd.Flags().StringP("retention-keep-dependencies", "d", "true", "Retain SBOMs that have dependencies")
}

func UploadCommand(cmd *cobra.Command, args []string) {
	flagRetentionPolicy, _ := cmd.Flags().GetString("retention-policy")
	flagRetentionKeep, _ := cmd.Flags().GetString("retention-keep")
	flagRetentionKeepDependencies, _ := cmd.Flags().GetString("retention-keep-dependencies")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug

	if len(args) < 1 {
		log.Fatal("missing required argument <sbom>...")
	}

	c := client.NewObserverClient()

	progress := log.NewProgressBar(int64(len(args)), "Uploading BOMs", flagSilent)

	fields := map[string]string{}

	if flagRetentionPolicy != "" {
		fields["retention-policy"] = flagRetentionPolicy

		if flagRetentionKeep != "" {
			fields["retention-keep"] = flagRetentionKeep
		}

		if flagRetentionKeepDependencies != "" {
			fields["retention-keep-dependencies"] = flagRetentionKeepDependencies
		}
	}

	for _, file := range args {
		err := c.UploadFile(file, fields)
		if err != nil {
			log.Error("error uploading", "file", file, "err", err)
			os.Exit(1)
		}

		_ = progress.Add(1)
	}

	_ = progress.Finish()
	_ = progress.Clear()

	log.Printf("Uploaded %d BOM(s)", len(args))
}
