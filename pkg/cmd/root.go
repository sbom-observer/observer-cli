package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "observer",
	Short: "Create, manage and upload SBOMs to https://sbom.observer",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },

	Version: "0.1",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// setup logging
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cli.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().Bool("debug", false, "Enable debug logging")
}

func NotImplemented(cmd *cobra.Command, args []string) {
	_, _ = fmt.Fprintf(os.Stderr, "not implemented\n")
	os.Exit(1)
}
