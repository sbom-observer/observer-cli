package execx

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FileEntry represents a file within a CAB archive
type FileEntry struct {
	Name           string
	Size           int64
	CompressedSize int64
	ModTime        time.Time
}

// IsExpandAvailable checks if Windows expand.exe is available
func IsExpandAvailable() bool {
	_, err := Exec("expand", "/?")
	return err == nil
}

// IsCabextractAvailable checks if cabextract is available (Linux/macOS)
func IsCabextractAvailable() bool {
	_, err := Exec("cabextract", "--version")
	return err == nil
}

// ListCABContents lists the contents of a CAB file without extracting
func ListCABContents(cabPath string) ([]FileEntry, error) {
	// Try expand first (Windows)
	if IsExpandAvailable() {
		return listCABWithExpand(cabPath)
	}

	// Try cabextract (Linux/macOS)
	if IsCabextractAvailable() {
		return listCABWithCabextract(cabPath)
	}

	return nil, fmt.Errorf("no suitable CAB listing tool available")
}

// listCABWithExpand lists CAB contents using Windows expand.exe
func listCABWithExpand(cabPath string) ([]FileEntry, error) {
	// expand -D cab_file lists contents without extracting
	output, err := Exec("expand", "-D", cabPath)
	if err != nil {
		return nil, fmt.Errorf("expand command failed: %w", err)
	}

	return parseExpandOutput(output)
}

// listCABWithCabextract lists CAB contents using cabextract
func listCABWithCabextract(cabPath string) ([]FileEntry, error) {
	// cabextract -l cab_file lists contents without extracting
	output, err := Exec("cabextract", "-l", cabPath)
	if err != nil {
		return nil, fmt.Errorf("cabextract command failed: %w", err)
	}

	return parseCabextractOutput(output)
}

// ExtractCABWithTool extracts a CAB file using the best available tool
func ExtractCABWithTool(cabPath, outputDir string) error {
	// Try expand first (Windows)
	if IsExpandAvailable() {
		return extractCABWithExpand(cabPath, outputDir)
	}

	// Try cabextract (Linux/macOS)
	if IsCabextractAvailable() {
		return extractCABWithCabextract(cabPath, outputDir)
	}

	return fmt.Errorf("no suitable CAB extraction tool available")
}

// extractCABWithExpand extracts CAB using Windows expand.exe
func extractCABWithExpand(cabPath, outputDir string) error {
	// expand cab_file -F:* output_dir
	_, err := Exec("expand", cabPath, "-F:*", outputDir)
	if err != nil {
		return fmt.Errorf("expand extraction failed: %w", err)
	}
	return nil
}

// extractCABWithCabextract extracts CAB using cabextract
func extractCABWithCabextract(cabPath, outputDir string) error {
	// cabextract -d output_dir cab_file
	_, err := Exec("cabextract", "-d", outputDir, cabPath)
	if err != nil {
		return fmt.Errorf("cabextract extraction failed: %w", err)
	}
	return nil
}

// parseExpandOutput parses the output from expand -D command
func parseExpandOutput(output string) ([]FileEntry, error) {
	var entries []FileEntry
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// expand -D output format (approximate):
		// Microsoft (R) File Expansion Utility Version 10.0.19041.1
		// Copyright (c) Microsoft Corporation. All rights reserved.
		//
		// Cabinet archive.cab
		//
		//   Date      Time    Attr         Size   Compressed  Name
		// ---------- ----- ---------- ---------- ----------  ------------------------
		// 09/15/2021  2:34p A---           1234        567  filename.txt

		// Look for lines that start with a date pattern
		if strings.Contains(line, "/") && (strings.Contains(line, "p ") || strings.Contains(line, "a ")) {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				// Try to parse the file entry
				if entry, err := parseExpandLine(parts); err == nil {
					entries = append(entries, entry)
				}
			}
		}
	}

	return entries, nil
}

// parseExpandLine parses a single line from expand -D output
func parseExpandLine(parts []string) (FileEntry, error) {
	var entry FileEntry

	// Format: Date Time Attr Size Compressed Name...
	if len(parts) < 6 {
		return entry, fmt.Errorf("insufficient parts in line")
	}

	// Parse size (parts[4])
	if size, err := strconv.ParseInt(parts[4], 10, 64); err == nil {
		entry.Size = size
	}

	// Parse compressed size (parts[5])
	if compressed, err := strconv.ParseInt(parts[5], 10, 64); err == nil {
		entry.CompressedSize = compressed
	}

	// Name is everything from parts[6] onwards
	if len(parts) > 6 {
		entry.Name = strings.Join(parts[6:], " ")
	}

	return entry, nil
}

// parseCabextractOutput parses the output from cabextract -l command
func parseCabextractOutput(output string) ([]FileEntry, error) {
	var entries []FileEntry
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Viewing") || strings.HasPrefix(line, "Cabinet") {
			continue
		}

		// cabextract -l output format:
		// Viewing cabinet: archive.cab
		//  File size | Date       Time     | Name
		// -----------+---------------------+-------------
		//       1234 | 15.09.2021 14:34:56 | filename.txt

		// Look for lines with pipe separators
		if strings.Contains(line, "|") {
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				if entry, err := parseCabextractLine(parts); err == nil {
					entries = append(entries, entry)
				}
			}
		}
	}

	return entries, nil
}

// parseCabextractLine parses a single line from cabextract -l output
func parseCabextractLine(parts []string) (FileEntry, error) {
	var entry FileEntry

	if len(parts) < 3 {
		return entry, fmt.Errorf("insufficient parts in line")
	}

	// Parse size (first part)
	sizeStr := strings.TrimSpace(parts[0])
	if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
		entry.Size = size
		entry.CompressedSize = size // cabextract doesn't show compressed size separately
	}

	// Name (third part)
	entry.Name = strings.TrimSpace(parts[2])

	// TODO: Parse date/time from parts[1] if needed
	// Format: "15.09.2021 14:34:56"

	return entry, nil
}