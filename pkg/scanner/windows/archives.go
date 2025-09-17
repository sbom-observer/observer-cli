package windows

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sbom-observer/observer-cli/pkg/execx"
	"github.com/sbom-observer/observer-cli/pkg/log"
)

// CreateTempDir creates a secure temporary directory for archive extraction
func CreateTempDir() (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "observer-installer-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	log.Debug("created temp directory", "path", tempDir)

	cleanup := func() {
		// TODO: uncomment when debugging is done!
		//if err := os.RemoveAll(tempDir); err != nil {
		//	log.Error("failed to cleanup temp directory", "dir", tempDir, "error", err)
		//}
	}

	return tempDir, cleanup, nil
}

// ExtractCAB extracts a CAB archive to the specified directory using external tools
func ExtractCAB(cabPath string, extractDir string) error {
	// Ensure extract directory exists
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create extract directory: %w", err)
	}

	// Try platform-specific extraction tools
	if err := extractCABWithExpandTool(cabPath, extractDir); err == nil {
		log.Debug("extracted CAB using expand tool", "cab", cabPath, "target", extractDir)
		return nil
	}

	if err := extractCABWithCabextract(cabPath, extractDir); err == nil {
		log.Debug("extracted CAB using cabextract tool", "cab", cabPath, "target", extractDir)
		return nil
	}

	return fmt.Errorf("no suitable CAB extraction tool available")
}

// extractCABWithExpandTool uses Windows expand.exe to extract CAB files
func extractCABWithExpandTool(cabPath, extractDir string) error {
	// Check if expand is available
	if !IsExpandAvailable() {
		return fmt.Errorf("expand tool not available")
	}

	// Use expand command: expand cab_file -F:* extract_dir
	args := []string{cabPath, "-F:*", extractDir}
	_, err := execx.Exec("expand", args...)
	if err != nil {
		return fmt.Errorf("expand command failed: %w", err)
	}

	return nil
}

// extractCABWithCabextract uses cabextract to extract CAB files on Unix systems
func extractCABWithCabextract(cabPath, extractDir string) error {
	// Check if cabextract is available
	if !IsCabextractAvailable() {
		return fmt.Errorf("cabextract tool not available")
	}

	// Use cabextract command: cabextract -d extract_dir cab_file
	args := []string{"-d", extractDir, cabPath}
	_, err := execx.Exec("cabextract", args...)
	if err != nil {
		return fmt.Errorf("cabextract command failed: %w", err)
	}

	return nil
}

// ExtractZIP extracts a ZIP archive to the specified directory using Go's standard library
func ExtractZIP(filePath string, extractDir string) error {
	// Open ZIP file
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer reader.Close()

	// Ensure extract directory exists
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create extract directory: %w", err)
	}

	// Extract each file
	for _, file := range reader.Reader.File {
		if err := extractZIPFile(file, extractDir); err != nil {
			log.Error("failed to extract ZIP file", "file", file.Name, "error", err)
			// Continue with other files rather than failing completely
		}
	}

	log.Debug("extracted ZIP archive", "files", len(reader.Reader.File), "target", extractDir)
	return nil
}

// extractZIPFile extracts a single file from a ZIP archive
func extractZIPFile(file *zip.File, extractDir string) error {
	// Open the file in the ZIP archive
	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open file in ZIP: %w", err)
	}
	defer rc.Close()

	// Create the full path for extraction
	path := filepath.Join(extractDir, file.Name)

	// Check for ZipSlip vulnerability
	if !isValidExtractPath(path, extractDir) {
		return fmt.Errorf("invalid file path in ZIP: %s", file.Name)
	}

	// Create directory if needed
	if file.FileInfo().IsDir() {
		if err := os.MkdirAll(path, file.FileInfo().Mode()); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		return nil
	}

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directories: %w", err)
	}

	// Create and write the file
	outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)
	if err != nil {
		return fmt.Errorf("failed to write file contents: %w", err)
	}

	return nil
}

// isValidExtractPath checks if the extraction path is safe (prevents ZipSlip attacks)
func isValidExtractPath(path, extractDir string) bool {
	// Get absolute paths
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	absExtractDir, err := filepath.Abs(extractDir)
	if err != nil {
		return false
	}

	// Check if the path is within the extract directory
	rel, err := filepath.Rel(absExtractDir, absPath)
	if err != nil {
		return false
	}

	// Reject paths that go outside the extract directory
	return !filepath.IsAbs(rel) && !hasTraversalPrefix(rel)
}

// hasTraversalPrefix checks if a path has directory traversal sequences
func hasTraversalPrefix(path string) bool {
	return filepath.HasPrefix(path, "..") || filepath.HasPrefix(path, "/../")
}

// ExtractArchive extracts an embedded archive based on its type
func ExtractArchive(archiveType ArchiveType, filePath string, extractDir string) error {
	switch archiveType {
	case ArchiveCAB:
		return ExtractCAB(filePath, extractDir)
	case ArchiveZIP:
		return ExtractZIP(filePath, extractDir)
	default:
		return fmt.Errorf("unsupported archive type: %v", archiveType)
	}
}

func IsExpandAvailable() bool {
	_, err := execx.Exec("expand", "/?")
	return err == nil
}

func IsCabextractAvailable() bool {
	_, err := execx.Exec("cabextract", "--version")
	return err == nil
}
