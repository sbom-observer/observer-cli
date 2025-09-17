package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sbom-observer/observer-cli/pkg/log"
)

// Inventory represents a complete file inventory from extracted archives
type Inventory []InventoryFile

// InventoryFile represents a single file in the inventory
type InventoryFile struct {
	Filename         string
	InstallationPath string
	SHA256           string
	Size             int64
	IsArchive        bool
	IsInstaller      bool
	ArchiveFormat    ArchiveType

	// PE data
	Meta *ExecutableFileMetadata

	SourceFilePath string // for debugging

	//MSIComponent     string // from MSI Component table
	//ArchiveSource    string // which archive this file came from
	//BurnPayloadID    string // ID from BurnManifest
	//PackageType      string // "UX", "MSI", "MSU", or "Unknown"
	//PackageID        string // Package ID from BurnManifest
	//ProductCode      string // MSI Product Code

	Contents []InventoryFile
}

// ScanFile creates an InventoryFile from an absolute path to a file on disk (recursively)
func ScanFile(filePath string) (InventoryFile, error) {
	log.Debugf("windows - Scanning file %s", filePath)

	info, err := os.Stat(filePath)
	if err != nil {
		return InventoryFile{}, fmt.Errorf("failed to stat file: %w", err)
	}

	// Calculate SHA-256 hash
	hash, err := hashFileSHA256(filePath)
	if err != nil {
		log.Error("failed to calculate file hash", "file", filePath, "error", err)
		hash = "" // Continue without hash
	}

	file := InventoryFile{
		Filename:       filepath.Base(filePath),
		SHA256:         hash,
		Size:           info.Size(),
		SourceFilePath: filePath,
	}

	// Extract version information if it's a PE file
	if isPEFile(filepath.Ext(filePath)) {
		meta, err := ExtractPEMetadata(filePath)
		if err != nil {
			log.Error("failed to extract PE metadata", "file", filePath, "error", err)
		}

		if meta != nil {
			file.Meta = meta
		}
	}

	// Carve out any embedded archives in executables
	if IsExecutable(filePath) {
		embeds, cleanup, err := extractEmbeddedArchives(filePath)
		if err != nil {
			log.Error("failed to extract embedded archives", "file", filePath, "error", err)
		}

		defer cleanup()

		if len(embeds) > 0 {
			log.Debugf("found %d embedded archives", len(embeds))

			file.IsInstaller = true

			//for _, embed := range embeds {
			//	embedFile, err := ScanFile(embed)
			//	if err != nil {
			//		log.Error("failed to scan embedded file", "file", filePath, "error", err)
			//		continue
			//	}
			//
			//	file.Contents = append(file.Contents, embedFile)
			//}
		}
	}

	// Determine if this is an archive
	file.IsArchive = isArchiveFile(filePath)
	if file.IsArchive {
		file.ArchiveFormat = ArchiveType(strings.TrimPrefix(strings.ToLower(filepath.Ext(filePath)), "."))
		file, err = scanArchive(file)
		if err != nil {
			log.Error("failed to scan archive", "file", filePath, "error", err)
			return file, nil // best effort - return any info we have
		}
	}

	return file, nil

}

func ScanDirectory(filePath string) (Inventory, error) {
	var inventory Inventory

	err := filepath.WalkDir(filePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Error("error walking directory", "path", path, "error", err)
			return nil // Continue walking despite errors
		}

		if d.IsDir() {
			return nil
		}

		// TODO: filter files
		//if !shouldIncludeFile(filePath) {
		//	return nil
		//}

		invFile, err := ScanFile(path)
		if err != nil {
			log.Error("error walking file", "path", path, "error", err)
			return nil // Continue walking despite errors
		}

		inventory = append(inventory, invFile)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return inventory, nil
}

func scanArchive(file InventoryFile) (InventoryFile, error) {
	log.Debug("windows - scanning archive", "path", file.SourceFilePath, "archiveType", file.ArchiveFormat)

	// Create temp directory for nested extraction
	// TODO: move tempdir to ExtractArchive
	tempDir, cleanup, err := CreateTempDir()
	if err != nil {
		return file, fmt.Errorf("failed to create temp dir for nested archive: %w", err)
	}
	defer cleanup()

	// extract the archive
	err = ExtractArchive(file.ArchiveFormat, file.SourceFilePath, tempDir)
	if err != nil {
		return file, fmt.Errorf("failed to extract nested archive: %w", err)
	}

	contents, err := ScanDirectory(tempDir)
	if err != nil {
		return file, fmt.Errorf("failed to scan nested archive: %w", err)
	}

	// Try to enrich with BurnManifest data if available
	enrichedContents, err := EnrichInventoryWithBurnManifest(contents, tempDir)
	if err != nil {
		log.Debug("failed to enrich with BurnManifest", "error", err)
		// Not a fatal error - continue without BurnManifest enrichment
	}

	if len(enrichedContents) > 0 {
		contents = enrichedContents
	}

	file.Contents = append(file.Contents, contents...)

	return file, nil
}

// hashFileSHA256 calculates the SHA-256 hash of a file
func hashFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// isArchiveFile determines if a file extension indicates an archive
func isArchiveFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	archiveExts := []string{".cab", ".zip", ".msi", ".msu", ".7z", ".rar", ".tar", ".gz"}

	for _, archiveExt := range archiveExts {
		if ext == archiveExt {
			return true
		}
	}
	return false
}

// isPEFile determines if a file extension indicates a PE executable
func isPEFile(ext string) bool {
	ext = strings.ToLower(ext)
	for _, peExt := range PeExtensions {
		if ext == peExt {
			return true
		}
	}
	return false
}

// shouldIncludeFile determines if a file should be included in the inventory
// We only care about PE files and archives, not UI resources
func shouldIncludeFile(file InventoryFile) bool {
	// Always include archives for recursive processing
	if file.IsArchive {
		return true
	}

	// Always include PE files (executables, libraries, drivers, etc.)
	if isPEFile(filepath.Ext(file.Filename)) {
		return true
	}

	// Include specific important file types
	ext := strings.ToLower(filepath.Ext(file.Filename))
	importantExts := []string{
		".exe", ".dll", ".sys", ".drv", ".com", ".scr", // PE files
		".msi", ".msu", ".cab", ".zip", ".7z", // Archives/installers
		".inf", ".cat", ".cer", ".crt", // Driver/certificate files
	}

	for _, importantExt := range importantExts {
		if ext == importantExt {
			return true
		}
	}

	// Exclude common UI/resource files
	excludeExts := []string{
		".xml", ".wxl", ".rtf", ".txt", ".log",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
		".html", ".htm", ".css", ".js",
	}

	for _, excludeExt := range excludeExts {
		if ext == excludeExt {
			return false
		}
	}

	// For files without extensions or unknown extensions,
	// check if they have specific names we care about
	return isImportantUnknownFile(file.Filename)
}

// shouldIncludeAfterBurnEnrichment determines if a file should be included after BurnManifest enrichment
// This is more specific than the general filtering - we use the real file path from BurnManifest
func shouldIncludeAfterBurnEnrichment(file InventoryFile) bool {
	// Use the installation path (real filename) if available, otherwise use the original filename
	checkPath := file.InstallationPath
	if checkPath == "" {
		checkPath = file.Filename
	}

	ext := strings.ToLower(filepath.Ext(checkPath))

	// Always include archives
	if file.IsArchive {
		return true
	}

	// Include PE files
	peExts := []string{
		".exe", ".dll", ".sys", ".drv", ".com", ".scr", ".ocx", ".ax", ".cpl",
		".efi", ".mui", ".tsp", ".mun", ".msstyles",
	}
	for _, peExt := range peExts {
		if ext == peExt {
			return true
		}
	}

	// Include installer/archive files
	archiveExts := []string{
		".msi", ".msu", ".cab", ".zip", ".7z", ".rar", ".tar", ".gz",
	}
	for _, archiveExt := range archiveExts {
		if ext == archiveExt {
			return true
		}
	}

	// Include driver and certificate files
	driverExts := []string{
		".inf", ".cat", ".cer", ".crt", ".pem",
	}
	for _, driverExt := range driverExts {
		if ext == driverExt {
			return true
		}
	}

	// Exclude common UI/resource files that we don't care about for SBOM
	excludeExts := []string{
		".xml", ".wxl", ".rtf", ".txt", ".log", ".md",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
		".html", ".htm", ".css", ".js", ".json",
		".wav", ".mp3", ".avi", ".mp4",
	}
	for _, excludeExt := range excludeExts {
		if ext == excludeExt {
			return false
		}
	}

	// If we can't determine the type, default to excluding it for UX payloads
	// (this helps filter out theme files, license files, etc.)
	return false
}

// shouldIncludeFileBasic applies basic filtering for files not found in BurnManifest
func shouldIncludeFileBasic(file InventoryFile) bool {
	// Always include archives for recursive processing
	if file.IsArchive {
		return true
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))

	// Include PE files
	peExts := []string{
		".exe", ".dll", ".sys", ".drv", ".com", ".scr", ".ocx", ".ax", ".cpl",
		".efi", ".mui", ".tsp", ".mun", ".msstyles",
	}
	for _, peExt := range peExts {
		if ext == peExt {
			return true
		}
	}

	// Include installer/archive files
	archiveExts := []string{
		".msi", ".msu", ".cab", ".zip", ".7z", ".rar", ".tar", ".gz",
	}
	for _, archiveExt := range archiveExts {
		if ext == archiveExt {
			return true
		}
	}

	// Include driver and certificate files
	driverExts := []string{
		".inf", ".cat", ".cer", ".crt", ".pem",
	}
	for _, driverExt := range driverExts {
		if ext == driverExt {
			return true
		}
	}

	// For files without extensions, be conservative and include them
	// (they might be important but just lack extensions)
	if ext == "" {
		return true
	}

	// Exclude known UI/resource file types
	excludeExts := []string{
		".xml", ".wxl", ".rtf", ".txt", ".log", ".md",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
		".html", ".htm", ".css", ".js", ".json",
	}
	for _, excludeExt := range excludeExts {
		if ext == excludeExt {
			return false
		}
	}

	// Default to including unknown extensions
	return true
}

// isImportantUnknownFile checks if a file without extension is important
func isImportantUnknownFile(filename string) bool {
	// Files that are important but may not have extensions
	importantNames := []string{
		"setup", "install", "uninstall",
		"driver", "service",
	}

	lowerName := strings.ToLower(filename)
	for _, name := range importantNames {
		if strings.Contains(lowerName, name) {
			return true
		}
	}

	return false
}
