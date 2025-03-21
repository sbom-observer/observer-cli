package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"sbom.observer/cli/pkg/cdxutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"sbom.observer/cli/pkg/log"
)

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare two SBOMs and show the differences",
	Long:  `Compare two SBOMs and show the differences. Only JSON CycloneDX SBOMs are currently supported.`,
	Run:   RunDiffCommand,
	Args:  cobra.MinimumNArgs(2),
}

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().BoolP("all", "a", false, "Output all components, not just the differences (default: false)")
	diffCmd.Flags().StringP("output", "o", "", "Output file for the results (default: stdout)")
	diffCmd.Flags().BoolP("include-purl", "p", false, "Include PURLs in the output (default: false)")
	diffCmd.Flags().BoolP("markdown", "m", false, "Output in markdown format (default: false)")
}

func RunDiffCommand(cmd *cobra.Command, args []string) {
	flagOutput, _ := cmd.Flags().GetString("output")
	flagAll, _ := cmd.Flags().GetBool("all")
	flagIncludePurl, _ := cmd.Flags().GetBool("include-purl")
	flagMarkdown, _ := cmd.Flags().GetBool("markdown")
	if len(args) != 2 {
		log.Fatal("filenames to two SBOMs are required as arguments")
	}

	fileOne := args[0]
	fileTwo := args[1]

	log.Debugf("Comparing %s and %s", fileOne, fileTwo)

	bomOne, err := cdxutil.ParseCycloneDX(fileOne)
	if err != nil {
		log.Fatalf("failed to parse %s. Error: %v", fileOne, err)
	}

	bomTwo, err := cdxutil.ParseCycloneDX(fileTwo)
	if err != nil {
		log.Fatalf("failed to parse %s. Error: %v", fileTwo, err)
	}

	result := diffBOMs(bomOne, bomTwo)
	result.NameOne = filepath.Base(fileOne)
	result.NameTwo = filepath.Base(fileTwo)

	output := renderResult(bomOne, bomTwo, result, !flagAll, flagIncludePurl, flagMarkdown)

	if flagOutput != "" {
		err = os.WriteFile(flagOutput, []byte(output), 0644)
		if err != nil {
			log.Fatalf("failed to write output to %s. Error: %v", flagOutput, err)
		}
	} else {
		fmt.Println(output)
	}
}

func renderResult(bomOne, bomTwo *cdx.BOM, result *diffResult, skipEqual bool, includePurl bool, renderMarkdown bool) string {
	var buffer bytes.Buffer

	// render bom metadata
	t := table.NewWriter()
	t.AppendHeader(table.Row{"", result.NameOne, result.NameTwo})
	t.AppendRow(table.Row{"BOMRef", bomOne.Metadata.Component.BOMRef, bomTwo.Metadata.Component.BOMRef})
	t.AppendRow(table.Row{"Type", bomOne.Metadata.Component.Type, bomTwo.Metadata.Component.Type})
	t.AppendRow(table.Row{"Name", bomOne.Metadata.Component.Name, bomTwo.Metadata.Component.Name})
	t.AppendRow(table.Row{"Group", bomOne.Metadata.Component.Group, bomTwo.Metadata.Component.Group})
	t.AppendRow(table.Row{"Version", bomOne.Metadata.Component.Version, bomTwo.Metadata.Component.Version})
	t.AppendRow(table.Row{"Author", bomOne.Metadata.Component.Author, bomTwo.Metadata.Component.Author})
	t.AppendRow(table.Row{"Copyright", bomOne.Metadata.Component.Copyright, bomTwo.Metadata.Component.Copyright})

	buffer.WriteString("Metadata\n")
	if renderMarkdown {
		buffer.WriteString(t.RenderMarkdown())
	} else {
		buffer.WriteString(t.Render())
	}
	buffer.WriteString("\n\n")

	// render components
	versionCountOne := 0
	versionCountTwo := 0

	for _, component := range result.Components {
		versionCountOne += len(component.VersionsInBomOne)
		versionCountTwo += len(component.VersionsInBomTwo)
	}

	t = table.NewWriter()
	headerRow := table.Row{"#", "", "Name", result.NameOne, "Scope", result.NameTwo, "Scope"}
	if includePurl {
		headerRow = append(headerRow, result.NameOne, result.NameTwo)
	}
	t.AppendHeader(headerRow)

	for i, component := range result.Components {
		isEqual := len(component.VersionsInBomOne) == len(component.VersionsInBomTwo)

		if isEqual {
			for _, versionOne := range component.VersionsInBomOne {
				if !slices.Contains(component.VersionsInBomTwo, versionOne) {
					isEqual = false
					break
				}
			}
		}

		if skipEqual && isEqual {
			continue
		}

		// green or red checkmark
		checkmark := "❌"
		if isEqual {
			checkmark = "✅"
		}

		// if there is no version i the second bom, add a [-] emoji, if there is no version in the first bom, add a [+] emoji
		if len(component.VersionsInBomOne) > len(component.VersionsInBomTwo) {
			checkmark = "-"
		} else if len(component.VersionsInBomOne) < len(component.VersionsInBomTwo) {
			checkmark = "+"
		}

		row := table.Row{
			i,
			checkmark,
			component.Name,
			strings.Join(component.VersionsInBomOne, ", "),
			component.ScopeInBomOne,
			strings.Join(component.VersionsInBomTwo, ", "),
			component.ScopeInBomTwo,
		}

		if includePurl {
			row = append(row, strings.Join(component.PurlsInBomOne, ", "), strings.Join(component.PurlsInBomTwo, ", "))
		}

		t.AppendRow(row)
	}

	t.AppendFooter(table.Row{len(result.Components), "", "", versionCountOne, "", versionCountTwo, ""})

	buffer.WriteString("Components\n")
	if renderMarkdown {
		buffer.WriteString(t.RenderMarkdown())
	} else {
		buffer.WriteString(t.Render())
	}
	buffer.WriteString("\n")

	return buffer.String()
}

type diffResult struct {
	NameOne    string
	NameTwo    string
	Components []componentDiff `json:"components"`
}

type componentDiff struct {
	Name             string   `json:"name"`
	VersionsInBomOne []string `json:"versionsInBomOne"`
	VersionsInBomTwo []string `json:"versionsInBomTwo"`
	PurlsInBomOne    []string `json:"purlsInBomOne"`
	PurlsInBomTwo    []string `json:"purlsInBomTwo"`
	ScopeInBomOne    string   `json:"scopeInBomOne"`
	ScopeInBomTwo    string   `json:"scopeInBomTwo"`
}

// diffBOMs compares two CycloneDX BOMs and returns a diffResult
// all components from both BOMs are returned
// handles boms with multiple components with the same name
func diffBOMs(bomOne, bomTwo *cdx.BOM) *diffResult {
	// Create a map to store component differences by name
	componentMap := make(map[string]*componentDiff)

	// Process components from first BOM
	if bomOne.Components != nil {
		for _, comp := range *bomOne.Components {
			name := comp.Name
			if comp.Group != "" {
				name = fmt.Sprintf("%s/%s", comp.Group, name)
			}
			if _, exists := componentMap[name]; !exists {
				componentMap[name] = &componentDiff{
					Name:             name,
					VersionsInBomOne: make([]string, 0),
					VersionsInBomTwo: make([]string, 0),
					PurlsInBomOne:    make([]string, 0),
					PurlsInBomTwo:    make([]string, 0),
				}
			}
			if comp.Version != "" {
				componentMap[name].VersionsInBomOne = append(componentMap[name].VersionsInBomOne, comp.Version)
			}
			if comp.PackageURL != "" {
				componentMap[name].PurlsInBomOne = append(componentMap[name].PurlsInBomOne, comp.PackageURL)
			}
			if comp.Scope != "" {
				componentMap[name].ScopeInBomOne = string(comp.Scope)
			}
		}
	}

	// Process components from second BOM
	if bomTwo.Components != nil {
		for _, comp := range *bomTwo.Components {
			name := comp.Name
			if comp.Group != "" {
				name = fmt.Sprintf("%s/%s", comp.Group, name)
			}
			if _, exists := componentMap[name]; !exists {
				componentMap[name] = &componentDiff{
					Name:             name,
					VersionsInBomOne: make([]string, 0),
					VersionsInBomTwo: make([]string, 0),
					PurlsInBomOne:    make([]string, 0),
					PurlsInBomTwo:    make([]string, 0),
				}
			}
			if comp.Version != "" {
				componentMap[name].VersionsInBomTwo = append(componentMap[name].VersionsInBomTwo, comp.Version)
			}
			if comp.PackageURL != "" {
				componentMap[name].PurlsInBomTwo = append(componentMap[name].PurlsInBomTwo, comp.PackageURL)
			}
			if comp.Scope != "" {
				componentMap[name].ScopeInBomTwo = string(comp.Scope)
			}
		}
	}

	// Convert map to slice of componentDiff
	components := make([]componentDiff, 0, len(componentMap))
	for _, diff := range componentMap {
		components = append(components, *diff)
	}

	// sort components by name
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	return &diffResult{
		Components: components,
	}
}
