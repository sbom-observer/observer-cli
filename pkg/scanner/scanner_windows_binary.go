package scanner

import (
	"path/filepath"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/files"
	"github.com/sbom-observer/observer-cli/pkg/ids"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/scanner/windows"
)

type WindowsBinaryScanner struct{}

func (s *WindowsBinaryScanner) Id() string {
	return "windows-binary"
}

func (s *WindowsBinaryScanner) IsAvailable() bool {
	return true
}

func (s *WindowsBinaryScanner) Priority() int {
	return 200
}

func (s *WindowsBinaryScanner) Scan(target *ScanTarget) error {
	bom := cdx.NewBOM()

	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Component: &cdx.Component{
			BOMRef: ids.NextUUID(),
			Name:   "windows-binary",
			Type:   cdx.ComponentTypeApplication,
			Properties: &[]cdx.Property{
				{
					// hint to merge that the contents of the BOM should be inlined
					Name:  "observer:internal:merge",
					Value: "inline",
				},
			},
		},
	}

	var components []cdx.Component

	for filename, ecosystem := range target.Files {
		log.Debug("scanning windows binary", "filename", filename, "ecosystem", ecosystem)

		absolutePath := filepath.Join(target.Path, filename)

		inventory, err := windows.ScanFile(absolutePath)
		if err != nil {
			log.Error("scanning windows binary", "path", absolutePath, "err", err)
			continue
		}

		component := toComponent(inventory)

		components = append(components, component)
	}

	if len(components) > 0 {
		bom.Components = &components
		target.Results = append(target.Results, bom)

		var refs []string
		for _, component := range components {
			refs = append(refs, component.BOMRef)
		}

		bom.Dependencies = &[]cdx.Dependency{
			{
				Ref:          bom.Metadata.Component.BOMRef,
				Dependencies: &refs,
			},
		}
	}

	return nil
}

func toComponent(file windows.InventoryFile) cdx.Component {
	fileComponent := cdx.Component{
		BOMRef: ids.NextUUID(),
		Type:   cdx.ComponentTypeFile,
		Name:   file.Filename,
		Hashes: &[]cdx.Hash{
			{
				Algorithm: cdx.HashAlgoSHA256,
				Value:     file.SHA256,
			},
		},
	}
	properties := []cdx.Property{}

	if file.Meta != nil {
		fileComponent.Version = file.Meta.FileVersion

		if file.Meta.OriginalFileName != "" {
			properties = append(properties, cdx.Property{
				Name:  "observer:file:originalFilename",
				Value: file.Meta.OriginalFileName,
			})
		}
	}

	if file.InstallationPath != "" {
		fileComponent.Name = files.WindowsBasePath(file.InstallationPath)
		properties = append(properties, cdx.Property{
			Name:  "observer:file:installationPath",
			Value: file.InstallationPath,
		})
		// TODO: add source name (u1 etc)
		properties = append(properties, cdx.Property{
			Name:  "observer:file:sourcePath",
			Value: file.SourceFilePath,
		})
	}

	if file.IsInstaller {
		properties = append(properties, cdx.Property{
			Name:  "observer:file:role",
			Value: "installer",
		})
	}

	/*
		properties := []cdx.Property{
			{
				Name:  "observer:file:size",
				Value: fmt.Sprintf("%d", file.Size),
			},
		}


		if file.ArchiveSource != "" {
			properties = append(properties, cdx.Property{
				Name:  "observer:archive:source",
				Value: file.ArchiveSource,
			})
		}

		if file.ArchiveFormat != "" {
			properties = append(properties, cdx.Property{
				Name:  "observer:archive:type",
				Value: file.ArchiveFormat,
			})
		}

		if file.PackageType != "" && file.PackageType != "Unknown" {
			properties = append(properties, cdx.Property{
				Name:  "observer:burn:packageType",
				Value: file.PackageType,
			})
		}


	*/

	if len(properties) > 0 {
		fileComponent.Properties = &properties
	}

	if len(file.Contents) > 0 {
		var childComponents []cdx.Component
		for _, containedFile := range file.Contents {
			childComponents = append(childComponents, toComponent(containedFile))
		}
		fileComponent.Components = &childComponents
	}

	// optionally wrap the file component in a semantic one
	ext := filepath.Ext(file.Filename)
	if file.Meta != nil && file.Meta.ProductName != "" && (ext == ".exe" || ext == ".dll") {
		component := cdx.Component{
			BOMRef:      ids.NextUUID(),
			Type:        cdx.ComponentTypeLibrary,
			Name:        file.Meta.ProductName,
			Version:     file.Meta.ProductVersion,
			Description: file.Meta.FileDescription,
			Copyright:   file.Meta.LegalCopyright,
		}

		if ext == ".exe" {
			component.Type = cdx.ComponentTypeApplication
		}

		if component.Version == "" && file.Meta.FileVersion != "" {
			component.Version = file.Meta.FileVersion
		}

		if component.Version == "" && file.Meta.AssemblyVersion != "" {
			component.Version = file.Meta.AssemblyVersion
		}

		if file.Meta.CompanyName != "" {
			component.Manufacturer = &cdx.OrganizationalEntity{
				Name: file.Meta.CompanyName,
			}
		}

		component.Components = &([]cdx.Component{
			fileComponent,
		})

		fileComponent = component
	}

	return fileComponent
}
