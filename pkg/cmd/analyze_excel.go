package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sbom-observer/observer-cli/pkg/client"
	"github.com/sbom-observer/observer-cli/pkg/types"
	"github.com/xuri/excelize/v2"
)

// Severity color styles (from template.xlsx)
var severityColors = map[string]string{
	"CRITICAL": "9900FF", // purple
	"HIGH":     "CC0000", // dark red
	"MEDIUM":   "FF9900", // orange
	"LOW":      "4A86E8", // blue
}

func renderExcelReport(filename string, result *client.SpeculateResponse) error {
	f := excelize.NewFile()
	defer f.Close()

	// Create sheets
	summarySheet := "Summary"
	vulnSheet := "Vulnerabilities"
	violationsSheet := "Policy Violations"
	licenseSheet := "License Summary"

	f.SetSheetName("Sheet1", summarySheet)
	f.NewSheet(vulnSheet)
	f.NewSheet(violationsSheet)
	f.NewSheet(licenseSheet)

	// Create styles
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"D9D9D9"}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border: []excelize.Border{
			{Type: "bottom", Color: "000000", Style: 1},
		},
	})

	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 14},
	})

	// Create severity styles
	severityStyles := make(map[string]int)
	for sev, color := range severityColors {
		style, _ := f.NewStyle(&excelize.Style{
			Font: &excelize.Font{Color: color, Bold: true},
		})
		severityStyles[sev] = style
	}

	// Report title
	title := fmt.Sprintf("Analysis Summary Report for %s %s (%s)",
		result.Subject.Name, result.Subject.Version, strings.ToLower(result.Subject.Type))

	createSummarySheet(f, summarySheet, result, headerStyle, severityStyles, titleStyle, title)
	createVulnerabilitiesSheet(f, vulnSheet, result, headerStyle, severityStyles, titleStyle, title)
	createViolationsSheet(f, violationsSheet, result, headerStyle, severityStyles, titleStyle, title)
	createLicenseSummarySheet(f, licenseSheet, result, headerStyle, titleStyle, title)

	f.SetActiveSheet(0)
	return f.SaveAs(filename)
}

func createVulnerabilitiesSheet(f *excelize.File, sheet string, result *client.SpeculateResponse, headerStyle int, severityStyles map[string]int, titleStyle int, title string) {
	// Title
	f.SetCellValue(sheet, "A1", title)
	f.SetCellStyle(sheet, "A1", "A1", titleStyle)

	vulnerabilities := result.Vulnerabilities

	// Sort by PackageName and PackageVersion
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if vulnerabilities[i].PackageName != vulnerabilities[j].PackageName {
			return vulnerabilities[i].PackageName < vulnerabilities[j].PackageName
		}
		return vulnerabilities[i].PackageVersion < vulnerabilities[j].PackageVersion
	})

	// Headers row 3 (merged)
	f.SetCellValue(sheet, "A3", "Package")
	f.MergeCell(sheet, "A3", "C3")
	f.SetCellValue(sheet, "D3", "Vulnerability")
	f.MergeCell(sheet, "D3", "J3")

	// Headers row 4
	headers := []string{"Name", "Version", "Ecosystem", "Identifier", "Analysis", "Severity", "EPSS", "Patched Versions", "Title", "Published"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 4)
		f.SetCellValue(sheet, cell, h)
	}

	// Apply header style to both rows
	for i := 1; i <= len(headers); i++ {
		cell1, _ := excelize.CoordinatesToCellName(i, 3)
		cell2, _ := excelize.CoordinatesToCellName(i, 4)
		f.SetCellStyle(sheet, cell1, cell1, headerStyle)
		f.SetCellStyle(sheet, cell2, cell2, headerStyle)
	}

	// Data rows
	for row, v := range vulnerabilities {
		rowNum := row + 5

		analysis := ""
		if v.Analysis != nil {
			analysis = v.Analysis.State
		}

		patchedVersions := ""
		if len(v.PatchedVersions) > 0 {
			patchedVersions = strings.Join(v.PatchedVersions, ", ")
		}

		severity := types.SeverityToString(v.Severity)

		date := ""
		if v.Published != nil {
			date = v.Published.Format("2006-01-02")
		}

		data := []interface{}{
			v.PackageName,
			v.PackageVersion,
			v.Ecosystem,
			v.VendorId,
			analysis,
			severity,
			fmt.Sprintf("%.2f%%", v.EPSS*100),
			patchedVersions,
			v.Title,
			date,
		}

		for col, val := range data {
			cell, _ := excelize.CoordinatesToCellName(col+1, rowNum)
			f.SetCellValue(sheet, cell, val)

			// Apply severity color
			if col == 5 { // Severity column
				if style, ok := severityStyles[severity]; ok {
					f.SetCellStyle(sheet, cell, cell, style)
				}
			}
		}
	}

	// Set column widths
	f.SetColWidth(sheet, "A", "A", 30)
	f.SetColWidth(sheet, "B", "B", 15)
	f.SetColWidth(sheet, "C", "C", 12)
	f.SetColWidth(sheet, "D", "D", 30)
	f.SetColWidth(sheet, "E", "E", 15)
	f.SetColWidth(sheet, "F", "F", 12)
	f.SetColWidth(sheet, "G", "G", 10)
	f.SetColWidth(sheet, "H", "H", 20)
	f.SetColWidth(sheet, "I", "I", 100)
	f.SetColWidth(sheet, "J", "J", 12)
}

func createViolationsSheet(f *excelize.File, sheet string, result *client.SpeculateResponse, headerStyle int, severityStyles map[string]int, titleStyle int, title string) {
	// Title
	f.SetCellValue(sheet, "A1", title)
	f.SetCellStyle(sheet, "A1", "A1", titleStyle)

	violations := result.Violations

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Violator.Name != violations[j].Violator.Name {
			return violations[i].Violator.Name < violations[j].Violator.Name
		}
		return violations[i].Violator.Version < violations[j].Violator.Version
	})

	// Headers row 3 (merged)
	f.SetCellValue(sheet, "A3", "Component")
	f.MergeCell(sheet, "A3", "B3")
	f.SetCellValue(sheet, "C3", "Policy Violation")
	f.MergeCell(sheet, "C3", "F3")

	// Headers row 4
	headers := []string{"Name", "Version", "Policy", "Message", "Severity", "Action"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 4)
		f.SetCellValue(sheet, cell, h)
	}

	// Apply header style
	for i := 1; i <= len(headers); i++ {
		cell1, _ := excelize.CoordinatesToCellName(i, 3)
		cell2, _ := excelize.CoordinatesToCellName(i, 4)
		f.SetCellStyle(sheet, cell1, cell1, headerStyle)
		f.SetCellStyle(sheet, cell2, cell2, headerStyle)
	}

	// Data rows
	for row, v := range violations {
		rowNum := row + 5

		violator := v.Violator.Name
		if v.Violator.Group != "" {
			violator = fmt.Sprintf("%s:%s", v.Violator.Group, v.Violator.Name)
		}

		severity := types.SeverityToString(v.Severity)

		data := []interface{}{
			violator,
			v.Violator.Version,
			v.PolicyName,
			v.Message,
			severity,
			v.Action,
		}

		for col, val := range data {
			cell, _ := excelize.CoordinatesToCellName(col+1, rowNum)
			f.SetCellValue(sheet, cell, val)

			// Apply severity color
			if col == 4 { // Severity column
				if style, ok := severityStyles[severity]; ok {
					f.SetCellStyle(sheet, cell, cell, style)
				}
			}
		}
	}

	// Set column widths
	f.SetColWidth(sheet, "A", "A", 35)
	f.SetColWidth(sheet, "B", "B", 15)
	f.SetColWidth(sheet, "C", "C", 25)
	f.SetColWidth(sheet, "D", "D", 50)
	f.SetColWidth(sheet, "E", "E", 12)
	f.SetColWidth(sheet, "F", "F", 15)
}

func createSummarySheet(f *excelize.File, sheet string, result *client.SpeculateResponse, headerStyle int, severityStyles map[string]int, titleStyle int, title string) {
	// Title
	f.SetCellValue(sheet, "A1", title)
	f.SetCellStyle(sheet, "A1", "A1", titleStyle)

	// Create severity header styles (bold + gray background + severity color)
	severityHeaderStyles := make(map[string]int)
	for sev, color := range severityColors {
		style, _ := f.NewStyle(&excelize.Style{
			Font:      &excelize.Font{Bold: true, Color: color},
			Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"D9D9D9"}},
			Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
			Border:    []excelize.Border{{Type: "bottom", Color: "000000", Style: 1}},
		})
		severityHeaderStyles[sev] = style
	}

	// Headers row 3 (merged)
	f.SetCellValue(sheet, "A3", " ")
	f.SetCellValue(sheet, "B3", "Issues per Severity")
	f.MergeCell(sheet, "B3", "G3")

	// Headers row 4
	headers := []string{" ", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NO RISK", "Total"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 4)
		f.SetCellValue(sheet, cell, h)
	}

	// Apply header style (row 3)
	for i := 1; i <= len(headers); i++ {
		cell1, _ := excelize.CoordinatesToCellName(i, 3)
		f.SetCellStyle(sheet, cell1, cell1, headerStyle)
	}

	// Apply header style (row 4) with severity colors
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 4)
		if style, ok := severityHeaderStyles[h]; ok {
			f.SetCellStyle(sheet, cell, cell, style)
		} else {
			f.SetCellStyle(sheet, cell, cell, headerStyle)
		}
	}

	// Vulnerabilities row
	vulnData := []interface{}{
		"Vulnerabilities",
		result.VulnerabilitiesSummary.Critical,
		result.VulnerabilitiesSummary.High,
		result.VulnerabilitiesSummary.Moderate,
		result.VulnerabilitiesSummary.Low,
		result.VulnerabilitiesSummary.NoRisk,
		result.VulnerabilitiesSummary.Total,
	}
	for col, val := range vulnData {
		cell, _ := excelize.CoordinatesToCellName(col+1, 5)
		f.SetCellValue(sheet, cell, val)
	}

	// Violations row
	violData := []interface{}{
		"Policy Violations",
		result.ViolationsSummary.Critical,
		result.ViolationsSummary.High,
		result.ViolationsSummary.Moderate,
		result.ViolationsSummary.Low,
		result.ViolationsSummary.NoRisk,
		result.ViolationsSummary.Total,
	}
	for col, val := range violData {
		cell, _ := excelize.CoordinatesToCellName(col+1, 6)
		f.SetCellValue(sheet, cell, val)
	}

	// Set column widths
	f.SetColWidth(sheet, "A", "A", 20)
	f.SetColWidth(sheet, "B", "G", 12)

	// Footer (6 rows below summary data which ends at row 6)
	footer := fmt.Sprintf("Report created %s by observer-cli (%s)", time.Now().Format("2006-01-02 15:04:05"), types.Version)
	f.SetCellValue(sheet, "A12", footer)
}

func createLicenseSummarySheet(f *excelize.File, sheet string, result *client.SpeculateResponse, headerStyle int, titleStyle int, title string) {
	// Title
	f.SetCellValue(sheet, "A1", title)
	f.SetCellStyle(sheet, "A1", "A1", titleStyle)

	licenses := result.LicenseSummary

	// Sort by count descending
	sort.Slice(licenses, func(i, j int) bool {
		return licenses[i].Count > licenses[j].Count
	})

	// Headers
	headers := []string{"License", "Count"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 3)
		f.SetCellValue(sheet, cell, h)
		f.SetCellStyle(sheet, cell, cell, headerStyle)
	}

	// Data rows
	for row, lic := range licenses {
		rowNum := row + 4
		f.SetCellValue(sheet, fmt.Sprintf("A%d", rowNum), lic.Id)
		f.SetCellValue(sheet, fmt.Sprintf("B%d", rowNum), lic.Count)
	}

	// Set column widths
	f.SetColWidth(sheet, "A", "A", 25)
	f.SetColWidth(sheet, "B", "B", 10)
}
