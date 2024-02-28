package cmd

import (
	"github.com/spf13/cobra"
)

// repoCmd represents the repo command
var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "Create an SBOM from a source repository (or monorepo) (TODO)",
	Long:  `Create an SBOM from a source repository (or monorepo) (TODO)`,
	Run:   NotImplemented,
}

func init() {
	rootCmd.AddCommand(repoCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// repoCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// repoCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
