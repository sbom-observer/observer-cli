package windows

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sbom-observer/observer-cli/pkg/log"
)

// BurnManifest represents the WiX Burn manifest structure
type BurnManifest struct {
	XMLName  xml.Name  `xml:"BurnManifest"`
	UX       UXElement `xml:"UX"`
	Chain    Chain     `xml:"Chain"`
	Payloads []Payload `xml:"Payload"`
}

// UXElement contains UI payloads
type UXElement struct {
	Payloads []Payload `xml:"Payload"`
}

// Chain contains the installation chain packages
type Chain struct {
	MsiPackages []MsiPackage `xml:"MsiPackage"`
	MsuPackages []MsuPackage `xml:"MsuPackage"`
}

// Payload represents a file payload in the manifest
type Payload struct {
	ID         string `xml:"Id,attr"`
	FilePath   string `xml:"FilePath,attr"`
	FileSize   string `xml:"FileSize,attr"`
	Hash       string `xml:"Hash,attr"`
	SourcePath string `xml:"SourcePath,attr"`
	Container  string `xml:"Container,attr"`
}

// MsiPackage represents an MSI package in the chain
type MsiPackage struct {
	ID          string       `xml:"Id,attr"`
	ProductCode string       `xml:"ProductCode,attr"`
	Version     string       `xml:"Version,attr"`
	PayloadRefs []PayloadRef `xml:"PayloadRef"`
}

// MsuPackage represents an MSU package in the chain
type MsuPackage struct {
	ID          string       `xml:"Id,attr"`
	KB          string       `xml:"KB,attr"`
	PayloadRefs []PayloadRef `xml:"PayloadRef"`
}

// PayloadRef references a payload by ID
type PayloadRef struct {
	ID string `xml:"Id,attr"`
}

// BurnPayloadInfo contains enriched payload information
type BurnPayloadInfo struct {
	ID          string
	FilePath    string
	FileSize    int64
	Hash        string
	SourcePath  string
	Container   string
	PackageType string // "UX", "MSI", "MSU", or "Unknown"
	PackageID   string
	ProductCode string
	Version     string
}

// ParseBurnManifest parses a BurnManifest XML file
func ParseBurnManifest(manifestPath string) (*BurnManifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifest BurnManifest
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest XML: %w", err)
	}

	log.Debug("parsed BurnManifest",
		"ux_payloads", len(manifest.UX.Payloads),
		"msi_packages", len(manifest.Chain.MsiPackages),
		"msu_packages", len(manifest.Chain.MsuPackages))

	return &manifest, nil
}

// GetPayloadInfo extracts comprehensive payload information from the manifest
func (m *BurnManifest) GetPayloadInfo() (map[string]*BurnPayloadInfo, error) {
	payloadMap := make(map[string]*BurnPayloadInfo)

	// Process UX payloads
	for _, payload := range m.UX.Payloads {
		info, err := createPayloadInfo(payload, "UX", "", "", "")
		if err != nil {
			log.Debug("failed to create UX payload info", "id", payload.ID, "error", err)
			continue
		}
		payloadMap[payload.SourcePath] = info
	}

	// Create maps for package lookup
	msiPackageMap := make(map[string]MsiPackage)
	for _, pkg := range m.Chain.MsiPackages {
		msiPackageMap[pkg.ID] = pkg
	}

	msuPackageMap := make(map[string]MsuPackage)
	for _, pkg := range m.Chain.MsuPackages {
		msuPackageMap[pkg.ID] = pkg
	}

	// Process all top-level payloads and match with packages
	allPayloads := append(m.UX.Payloads, m.Payloads...)
	for _, payload := range allPayloads {
		if payload.SourcePath == "" {
			continue
		}

		// Skip if already processed as UX payload
		if _, exists := payloadMap[payload.SourcePath]; exists {
			continue
		}

		// Try to find which package this payload belongs to
		packageType, packageID, productCode, version := findPayloadPackage(payload.ID, msiPackageMap, msuPackageMap)

		info, err := createPayloadInfo(payload, packageType, packageID, productCode, version)
		if err != nil {
			log.Debug("failed to create payload info", "id", payload.ID, "error", err)
			continue
		}

		payloadMap[payload.SourcePath] = info
	}

	log.Debug("created payload info map", "entries", len(payloadMap))
	return payloadMap, nil
}

// createPayloadInfo creates a BurnPayloadInfo from a payload
func createPayloadInfo(payload Payload, packageType, packageID, productCode, version string) (*BurnPayloadInfo, error) {
	fileSize, err := strconv.ParseInt(payload.FileSize, 10, 64)
	if err != nil {
		fileSize = 0
	}

	return &BurnPayloadInfo{
		ID:          payload.ID,
		FilePath:    payload.FilePath,
		FileSize:    fileSize,
		Hash:        payload.Hash,
		SourcePath:  payload.SourcePath,
		Container:   payload.Container,
		PackageType: packageType,
		PackageID:   packageID,
		ProductCode: productCode,
		Version:     version,
	}, nil
}

// findPayloadPackage finds which package a payload belongs to
func findPayloadPackage(payloadID string, msiPackages map[string]MsiPackage, msuPackages map[string]MsuPackage) (string, string, string, string) {
	// Check MSI packages
	for _, pkg := range msiPackages {
		for _, ref := range pkg.PayloadRefs {
			if ref.ID == payloadID {
				return "MSI", pkg.ID, pkg.ProductCode, pkg.Version
			}
		}
	}

	// Check MSU packages
	for _, pkg := range msuPackages {
		for _, ref := range pkg.PayloadRefs {
			if ref.ID == payloadID {
				return "MSU", pkg.ID, "", ""
			}
		}
	}

	return "Unknown", "", "", ""
}

// DetectBurnManifest looks for a BurnManifest file in the extracted directory
func DetectBurnManifest(extractDir string) (string, error) {
	// BurnManifest is typically in file "0"
	manifestPath := filepath.Join(extractDir, "0")
	if _, err := os.Stat(manifestPath); err == nil {
		// Verify it's actually XML
		if isBurnManifest(manifestPath) {
			return manifestPath, nil
		}
	}

	// Also check for other common names
	candidates := []string{"BurnManifest.xml", "manifest.xml"}
	for _, candidate := range candidates {
		manifestPath = filepath.Join(extractDir, candidate)
		if _, err := os.Stat(manifestPath); err == nil {
			if isBurnManifest(manifestPath) {
				return manifestPath, nil
			}
		}
	}

	return "", fmt.Errorf("BurnManifest not found in %s", extractDir)
}

// isBurnManifest checks if a file is a BurnManifest XML
func isBurnManifest(filePath string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	// Check for BurnManifest XML markers
	content := string(data)
	return strings.Contains(content, "<BurnManifest") || strings.Contains(content, "BurnManifest xmlns")
}

// EnrichInventoryWithBurnManifest enriches inventory files with BurnManifest metadata
func EnrichInventoryWithBurnManifest(files []InventoryFile, extractDir string) ([]InventoryFile, error) {
	manifestPath, err := DetectBurnManifest(extractDir)
	if err != nil {
		log.Debug("BurnManifest not found, skipping enrichment", "dir", extractDir, "error", err)
		return files, nil // Not an error - not all CAB files have BurnManifest
	}

	manifest, err := ParseBurnManifest(manifestPath)
	if err != nil {
		return files, fmt.Errorf("failed to parse BurnManifest: %w", err)
	}

	payloadInfo, err := manifest.GetPayloadInfo()
	if err != nil {
		return files, fmt.Errorf("failed to get payload info: %w", err)
	}

	// Enrich inventory files with BurnManifest data and apply filtering
	var filteredFiles []InventoryFile
	for _, file := range files {
		// Try to match by filename (source path)
		if info, exists := payloadInfo[file.Filename]; exists {
			enrichedFile := enrichFileWithPayloadInfo(file, info)

			// TODO: remove, we'll do filtering in inventory.go instead
			// Apply filtering after BurnManifest enrichment using real file path
			//if !shouldIncludeAfterBurnEnrichment(enrichedFile) {
			//	log.Debug("filtered out file after BurnManifest enrichment",
			//		"file", file.Filename,
			//		"real_path", info.FilePath,
			//		"package_type", info.PackageType)
			//	continue
			//}

			filteredFiles = append(filteredFiles, enrichedFile)
			log.Debug("enriched file with BurnManifest data",
				"file", file.Filename,
				"real_path", info.FilePath,
				"package_type", info.PackageType)
		} else {
			filteredFiles = append(filteredFiles, file)

			// TODO: remove, we'll do filtering in inventory.go instead
			//// File not found in BurnManifest, apply basic filtering
			//if shouldIncludeFileBasic(file) {
			//	filteredFiles = append(filteredFiles, file)
			//} else {
			//	log.Debug("filtered out file (no BurnManifest match)",
			//		"file", file.Filename)
			//}
		}
	}

	log.Debug("enriched inventory with BurnManifest data",
		"manifest", manifestPath,
		"payloads", len(payloadInfo),
		"files", len(filteredFiles))

	return filteredFiles, nil
}

// enrichFileWithPayloadInfo enriches an inventory file with payload information
func enrichFileWithPayloadInfo(file InventoryFile, info *BurnPayloadInfo) InventoryFile {
	// Use the real file path from the manifest if available
	if info.FilePath != "" {
		file.InstallationPath = info.FilePath
	}

	// TODO: Add version information if available when Version field is enabled
	//if file.Version == "" && info.Version != "" {
	//	file.Version = info.Version
	//}

	// TODO: Set BurnManifest-specific fields when these fields are enabled
	//file.BurnPayloadID = info.ID
	//file.PackageType = info.PackageType
	//file.PackageID = info.PackageID
	//file.ProductCode = info.ProductCode

	// TODO: Set MSI component if it's an MSI package when MSIComponent field is enabled
	//if info.PackageType == "MSI" {
	//	file.MSIComponent = info.PackageID
	//}

	return file
}

// GetPackageInfo returns information about packages in the manifest
func (m *BurnManifest) GetPackageInfo() []PackageInfo {
	var packages []PackageInfo

	// Add MSI packages
	for _, pkg := range m.Chain.MsiPackages {
		packages = append(packages, PackageInfo{
			ID:          pkg.ID,
			Type:        "MSI",
			ProductCode: pkg.ProductCode,
			Version:     pkg.Version,
			PayloadIDs:  getPayloadIDs(pkg.PayloadRefs),
		})
	}

	// Add MSU packages
	for _, pkg := range m.Chain.MsuPackages {
		packages = append(packages, PackageInfo{
			ID:         pkg.ID,
			Type:       "MSU",
			KB:         pkg.KB,
			PayloadIDs: getPayloadIDs(pkg.PayloadRefs),
		})
	}

	return packages
}

// PackageInfo represents package information from the manifest
type PackageInfo struct {
	ID          string
	Type        string
	ProductCode string
	Version     string
	KB          string
	PayloadIDs  []string
}

// getPayloadIDs extracts payload IDs from payload references
func getPayloadIDs(refs []PayloadRef) []string {
	var ids []string
	for _, ref := range refs {
		ids = append(ids, ref.ID)
	}
	return ids
}
