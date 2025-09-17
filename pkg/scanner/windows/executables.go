package windows

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/saferwall/pe"
	"github.com/sbom-observer/observer-cli/pkg/log"
)

// PeExtensions - extensions for Portable Executable (PE) files.
// This list may not be exhaustive, as the PE standard does not mandate specific extensions.
// The empty string is intentionally included to handle files without extensions.
var PeExtensions = []string{
	".acm", ".ax", ".cpl", ".dll", ".drv", ".efi", ".exe", ".mui", ".ocx",
	".scr", ".sys", ".tsp", ".mun", ".msstyles",
}

type ExecutableFileMetadata struct {
	// Path to the executable file
	FilePath string `json:"filePath,omitempty"`

	// Original file name
	OriginalFileName string `json:"originalFileName,omitempty"`

	// Assembly name
	AssemblyVersion string `json:"assemblyVersion,omitempty"`

	// Internal name of the product
	InternalName string `json:"internalName,omitempty"`

	// Product name
	ProductName string `json:"productName,omitempty"`

	// Product version
	ProductVersion string `json:"productVersion,omitempty"`

	// File description
	FileDescription string `json:"fileDescription,omitempty"`

	// File version
	FileVersion string `json:"fileVersion,omitempty"`

	// Company that produced the file
	CompanyName string `json:"companyName,omitempty"`

	// Copyright information
	LegalCopyright string `json:"legalCopyright,omitempty"`

	// Trademark information
	Trademark string `json:"trademark,omitempty"`

	// Comments
	Comments string `json:"comments,omitempty"`

	// Language/locale
	Language string `json:"language,omitempty"`

	// PE architecture (e.g., x86, x64, ARM)
	Architecture string `json:"architecture,omitempty"`

	// Timestamp from PE header
	Timestamp uint32 `json:"timestamp,omitempty"`
}

type ExecutableFile struct {
	Metadata ExecutableFileMetadata
	Path     string
	Includes []ExecutableFile
}

type ScanResult struct {
	Files []ExecutableFile
}

// hasPEMagicBytes checks if a given file has the PE magic bytes in the header
func hasPEMagicBytes(filePath string) (bool, error) {
	// check for the smallest PE size.
	size, err := fileSize(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to get file size: %w", err)
	}
	if size < pe.TinyPESize {
		return false, nil
	}

	// Open the file to read magic bytes
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var magic uint16
	if err := binary.Read(file, binary.LittleEndian, &magic); err != nil {
		return false, fmt.Errorf("failed to read magic bytes: %w", err)
	}

	// Validate if the magic bytes match any of the expected PE signatures
	hasPESignature := magic == pe.ImageDOSSignature || magic == pe.ImageDOSZMSignature

	return hasPESignature, nil
}

// fileSize returns the size of the file in bytes
func fileSize(filePath string) (int64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to get file info: %w", err)
	}
	return fileInfo.Size(), nil
}

func ExtractPEMetadata(filePath string) (*ExecutableFileMetadata, error) {
	if has, err := hasPEMagicBytes(filePath); err != nil {
		return nil, fmt.Errorf("failed to check if file is a PE file: %w", err)
	} else if !has {
		log.Debug("file is not a PE file", "filePath", filePath)
		return nil, nil
	}

	// Open the PE file
	f, err := pe.New(filePath, &pe.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to extract PE metadata: %w", err)
	}

	// Parse the PE file
	if err := f.Parse(); err != nil {
		return nil, fmt.Errorf("failed to extract PE metadata: %w", err)
	}

	// TODO: add tables extractions

	// If no inventory entries were found in CLR.MetadataTables check the VersionResources as a fallback
	// this is mostly required on .exe files
	versionResources, err := f.ParseVersionResources()
	if err != nil {
		return nil, fmt.Errorf("failed to extract PE version metadata: %w", err)
	}

	if len(versionResources) == 0 {
		log.Debug("No version resources found in PE file")
		return nil, nil
	}

	/*
			{
		  "CompanyName": "Microsoft Corporation",
		  "FileDescription": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
		  "FileVersion": "14.44.35211.0",
		  "InternalName": "setup",
		  "LegalCopyright": "Copyright (c) Microsoft Corporation. All rights reserved.",
		  "OriginalFilename": "VC_redist.x64.exe",
		  "ProductName": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
		  "ProductVersion": "14.44.35211.0"
		}
	*/

	meta := ExecutableFileMetadata{
		FilePath:         filePath,
		CompanyName:      versionResources["CompanyName"],
		FileDescription:  versionResources["FileDescription"],
		FileVersion:      versionResources["FileVersion"],
		InternalName:     versionResources["InternalName"],
		LegalCopyright:   versionResources["LegalCopyright"],
		OriginalFileName: versionResources["OriginalFilename"],
		ProductName:      versionResources["ProductName"],
		ProductVersion:   versionResources["ProductVersion"],
		AssemblyVersion:  versionResources["Assembly Version"],
	}

	return &meta, nil
}

// IsExecutable checks if the file is an executable based on its extension
func IsExecutable(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".exe"
}
