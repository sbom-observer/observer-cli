package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/aquasecurity/table"
	"github.com/liamg/tml"
	"github.com/sbom-observer/observer-cli/pkg/client"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Aliases: []string{"a"},
	Use:     "analyze <file>",
	Short:   "Analyze an SBOM using https://sbom.observer",
	Long: `This command will send the SBOM to the free service provided by https://sbom.observer 
for analysis and show the results.

SBOMs are uploaded to a temporary namespace and deleted after the request is processed.

For avanced features like custom policies, VEX support, failing builds in violations etc 
you need to create an account at https://sbom.observer and provide a token in the OBSERVER_TOKEN 
environment variable.

To use a custom namespace or endpoint, set the OBSERVER_ENDPOINT and OBSERVER_NAMESPACE environment variables.
	`,
	Run: AnalyzeCommand,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().Bool("fail", false, "exit(1) if any policy violations with action 'fail-build' are found")
	analyzeCmd.Flags().BoolP("summary", "s", false, "only output summaries")
}

func AnalyzeCommand(cmd *cobra.Command, args []string) {
	flagFail, _ := cmd.Flags().GetBool("fail")
	flagSummary, _ := cmd.Flags().GetBool("summary")

	if len(args) != 1 {
		log.Fatal("missing required argument <file>")
	}

	c := client.NewObserverClient()

	result, err := c.AnalyzeSBOM(args[0])
	if err != nil {
		log.Error("error analyzing", "file", args[0], "err", err)
		os.Exit(1)
	}

	log.Printf("Analyzed %s", args[0])

	fmt.Println()
	renderSpeculationResult(os.Stdout, result, flagSummary)
	fmt.Println()

	// highlight limitations
	if c.Config.Token == "" {
		log.Printf("Create an account at https://sbom.observer to create custom policies and support to fail the build")
	}

	// check any violation should fail the build
	if flagFail {
		violationFailActionCount := 0
		for _, v := range result.Violations {
			if v.Action == client.PolicyViolationActionFailBuild {
				violationFailActionCount++
			}
		}

		if violationFailActionCount > 0 {
			log.Errorf("Build failed due to %d policy violations with action='fail-build'", violationFailActionCount)
			os.Exit(1)
		}
	}
}

func renderSpeculationResult(w io.Writer, result *client.SpeculateResponse, summaryOnly bool) {
	isTerminalWriter := IsTerminalWriter(w)
	if !summaryOnly {
		renderSpeculativeVulnerabilities(w, isTerminalWriter, result)
		renderSpeculativeViolations(w, isTerminalWriter, result)
	}
	renderSpeculativeSummary(w, isTerminalWriter, result)
}

func renderSpeculativeVulnerabilities(w io.Writer, isTerminalWriter bool, result *client.SpeculateResponse) {
	vulnerabilities := result.Vulnerabilities

	// Sort vulnerabilities by PackageName and PackageVersion
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if vulnerabilities[i].PackageName != vulnerabilities[j].PackageName {
			return vulnerabilities[i].PackageName < vulnerabilities[j].PackageName
		}
		return vulnerabilities[i].PackageVersion < vulnerabilities[j].PackageVersion
	})

	// render table
	t := newTableWriter(w, isTerminalWriter)
	t.SetAutoMerge(true)
	t.SetAutoMergeHeaders(true)
	t.SetHeaders("Package", "Vulnerability")
	t.AddHeaders("Name", "Version", "Identifier", "Analysis", "Severity", "EPSS", "Patched Versions", "Title")
	t.SetHeaderColSpans(0, 2, 6)

	for _, v := range vulnerabilities {
		var analysis string
		if v.Analysis != nil {
			analysis = v.Analysis.State
		}

		patchedVersions := ""
		if len(v.PatchedVersions) > 0 {
			patchedVersions = strings.Join(v.PatchedVersions, ", ")
		}

		severity := ""
		if isTerminalWriter {
			severity = fmt.Sprintf("%s", colorizeSeverity(severityToString(v.Severity)))
		} else {
			severity = fmt.Sprintf("%s", severityToString(v.Severity))
		}

		t.AddRow(
			v.PackageName,
			v.PackageVersion,
			v.VendorId,
			analysis,
			severity,
			fmt.Sprintf("%.2f%%", v.EPSS*100),
			patchedVersions,
			v.Title,
		)
	}

	if len(vulnerabilities) < result.VulnerabilitiesSummary.Total {
		_, _ = fmt.Fprintf(w, " -- Top %d Vulnerabilities --\n", len(vulnerabilities))
	} else {
		_, _ = fmt.Fprintf(w, " -- Vulnerabilities --\n")
	}

	t.Render()

	_, _ = fmt.Fprintf(w, "\n\n")

}

func renderSpeculativeViolations(w io.Writer, isTerminalWriter bool, result *client.SpeculateResponse) {
	violations := result.Violations

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Violator.Name != violations[j].Violator.Name {
			return violations[i].Violator.Name < violations[j].Violator.Name
		}
		return violations[i].Violator.Version < violations[j].Violator.Version
	})

	// render table
	t := table.New(w)
	if isTerminalWriter {
		t.SetHeaderStyle(table.StyleBold)
		t.SetLineStyle(table.StyleDim)
	}
	t.SetAutoMerge(true)
	t.SetAutoMergeHeaders(true)
	t.SetHeaders("Component", "Policy Violation")
	t.AddHeaders("Name", "Version", "Policy", "Message", "Severity", "Action")
	t.SetHeaderColSpans(0, 2, 4)
	for _, v := range violations {
		violator := v.Violator.Name
		if v.Violator.Group != "" {
			violator = fmt.Sprintf("%s:%s", v.Violator.Group, v.Violator.Name)
		}

		severity := ""
		if isTerminalWriter {
			severity = fmt.Sprintf("%s", colorizeSeverity(severityToString(v.Severity)))
		} else {
			severity = fmt.Sprintf("%s", severityToString(v.Severity))
		}

		t.AddRow(
			violator,
			v.Violator.Version,
			v.PolicyName,
			v.Message,
			severity,
			v.Action,
		)
	}

	if len(violations) < result.ViolationsSummary.Total {
		_, _ = fmt.Fprintf(w, " -- Top %d Policy Violations --\n", len(violations))
	} else {
		_, _ = fmt.Fprintf(w, " -- Policy Violations --\n")
	}

	t.Render()

	_, _ = fmt.Fprintf(w, "\n\n")
}

func renderSpeculativeSummary(w io.Writer, isTerminalWriter bool, result *client.SpeculateResponse) {
	t := newTableWriter(w, isTerminalWriter)
	t.SetAutoMerge(false)
	t.SetAutoMergeHeaders(true)
	t.SetHeaders(" ", "Issues per Severity")
	t.AddHeaders(
		" ",
		colorizeSeverity("CRITICAL"),
		colorizeSeverity("HIGH"),
		colorizeSeverity("MEDIUM"),
		colorizeSeverity("LOW"),
		"NO RISK",
		"Total",
	)
	t.SetHeaderColSpans(0, 1, 6)

	t.AddRow(
		"Vulnerabilities",
		fmt.Sprintf("%d", result.VulnerabilitiesSummary.Critical),
		fmt.Sprintf("%d", result.VulnerabilitiesSummary.High),
		fmt.Sprintf("%d", result.VulnerabilitiesSummary.Moderate),
		fmt.Sprintf("%d", result.VulnerabilitiesSummary.Low),
		fmt.Sprintf("%d", result.VulnerabilitiesSummary.NoRisk),
		fmt.Sprintf("%d", result.VulnerabilitiesSummary.Total),
	)

	t.AddRow(
		"Policy Violations",
		fmt.Sprintf("%d", result.ViolationsSummary.Critical),
		fmt.Sprintf("%d", result.ViolationsSummary.High),
		fmt.Sprintf("%d", result.ViolationsSummary.Moderate),
		fmt.Sprintf("%d", result.ViolationsSummary.Low),
		fmt.Sprintf("%d", result.ViolationsSummary.NoRisk),
		fmt.Sprintf("%d", result.ViolationsSummary.Total),
	)

	_, _ = fmt.Fprintf(w, " -- Summary --\n")
	t.Render()
	_, _ = fmt.Fprintf(w, "\n\n")
}

func newTableWriter(w io.Writer, isTerminalWriter bool) *table.Table {
	t := table.New(w)

	// markdown
	/*
		t.SetDividers(table.MarkdownDividers)

		t.SetBorderTop(false)
		t.SetBorderBottom(false)
		t.SetRowLines(false)
	*/

	// bug: the table is not rendering correctly in some terminals
	if isTerminalWriter {
		availableWidth := 80
		if w == os.Stdout {
			width, _, _ := term.GetSize(int(os.Stdout.Fd()))
			if width > 0 {
				availableWidth = width
			}
		}
		if availableWidth > 200 {
			availableWidth = 200
		}
		t.SetAvailableWidth(availableWidth)
	}

	if isTerminalWriter {
		t.SetHeaderStyle(table.StyleBold)
		t.SetLineStyle(table.StyleDim)
	}

	return t
}

func severityToString(severity float64) string {
	if severity > 8.9 {
		return "CRITICAL"
	}

	if severity > 6.9 {
		return "HIGH"
	}

	if severity > 3.9 {
		return "MEDIUM"
	}

	if severity > 0 {
		return "LOW"
	}

	return "UNKNOWN"
}

func colorizeSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return tml.Sprintf("<magenta>%s</magenta>", severity)
	case "HIGH":
		return tml.Sprintf("<red>%s</red>", severity)
	case "MEDIUM":
		return tml.Sprintf("<yellow>%s</yellow>", severity)
	case "LOW":
		return tml.Sprintf("<blue>%s</blue>", severity)
	default:
		return tml.Sprintf("<gray>%s</gray>", severity)
	}
}

func IsTerminalWriter(output io.Writer) bool {
	if runtime.GOOS == "windows" {
		return false
	}

	if output != os.Stdout {
		return false
	}

	o, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	return (o.Mode() & os.ModeCharDevice) == os.ModeCharDevice
}
