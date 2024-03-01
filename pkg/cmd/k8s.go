package cmd

import (
	"sbom.observer/cli/pkg/k8s"

	"github.com/spf13/cobra"
)

// k8sCmd represents the k8s command
var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Create an environment snapshot, and optionally SBOMs, of a k8s cluster.",
	Long:  `Create an environment snapshot, and optionally SBOMs, of a k8s cluster.`,
	Run:   k8s.KubernetesCommand,
}

func init() {
	rootCmd.AddCommand(k8sCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// k8sCmd.PersistentFlags().String("foo", "", "A help for foo")

	// toggles
	k8sCmd.Flags().BoolP("sbom", "s", false, "Create SBOMs for all images found in the cluster")
	k8sCmd.Flags().BoolP("upload", "u", false, "Upload the results to https://sbom.observer")

	k8sCmd.Flags().String("scanner", "trivy", "SBOM scanner to use (default: trivy)")

	// output
	k8sCmd.Flags().StringP("output", "o", "", "Output directory for the results (default: stdout)")

	// selectors
	k8sCmd.Flags().StringSliceP("namespace", "n", nil, "Scan resources in this k8s namespace (default: all namespaces)")
	k8sCmd.Flags().String("kubeconfig", "", "Path to the kubeconfig file to use")
}
