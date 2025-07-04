package builds

import (
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/files"
	"github.com/sbom-observer/observer-cli/pkg/ids"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/ospkgs"
	"github.com/sbom-observer/observer-cli/pkg/types"
)

// https://json-schema.org/understanding-json-schema/reference/string.html#dates-and-times
const JsonSchemaDateTimeFormat = "2006-01-02T15:04:05+00:00"

func GenerateCycloneDX(deps *BuildDependencies, config types.ScanConfig) (*cdx.BOM, error) {
	createdAt := time.Now()

	bom := cdx.NewBOM()

	bom.Version = 1
	bom.SerialNumber = fmt.Sprintf("urn:uuid:%s", ids.NextUUID())

	bom.Metadata = &cdx.Metadata{
		Timestamp: createdAt.Format(JsonSchemaDateTimeFormat),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:      cdx.ComponentTypeApplication,
					Name:      "observer",
					Publisher: "https://sbom.observer",
					Version:   types.Version,
					ExternalReferences: &[]cdx.ExternalReference{
						{
							Type: cdx.ERTypeWebsite,
							URL:  "https://github.com/sbom-observer/observer-cli",
						},
					},
				},
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "build-observer",
					Version: "0.1", // TODO: should fetch from build-observer file
					ExternalReferences: &[]cdx.ExternalReference{
						{
							Type: cdx.ERTypeWebsite,
							URL:  "https://github.com/sbom-observer/build-observer",
							//Comment: "",
						},
					},
				},
			},
		},
		// https://cyclonedx.org/docs/1.5/json/#metadata_lifecycles
		Lifecycles: &[]cdx.Lifecycle{
			{
				Phase: cdx.LifecyclePhaseBuild,
			},
		},
	}

	// metadata component
	bom.Metadata.Component = &cdx.Component{
		BOMRef:  ids.NextUUID(),
		Type:    cdx.ComponentTypeApplication,
		Name:    config.Component.Name,
		Group:   config.Component.Group,
		Version: config.Component.Version,
	}

	if config.Component.Licenses != nil {
		bom.Metadata.Component.Licenses = config.Component.Licenses
	}

	if config.Supplier.Name != "" {
		bom.Metadata.Supplier = &config.Supplier
	}

	if config.Manufacturer.Name != "" {
		bom.Metadata.Manufacturer = &config.Manufacturer
	}

	if config.Author.Name != "" {
		bom.Metadata.Authors = &[]cdx.OrganizationalContact{
			config.Author,
		}
	}

	// components
	var components []cdx.Component
	var rootDependencies []string

	index := map[string]int{}

	for _, dep := range deps.Code {
		purl := purlForPackage(dep)

		if dep.IsSourcePackage {
			purl = fmt.Sprintf("pkg:generic/%s@%s", dep.Name, dep.Version)
		}

		component := cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       dep.Name,
			Version:    dep.Version,
			PackageURL: purl,
		}

		for _, license := range dep.Licenses {
			if component.Licenses == nil {
				component.Licenses = &cdx.Licenses{}
			}

			if license.Expression != "" {
				*component.Licenses = append(*component.Licenses, cdx.LicenseChoice{
					Expression: license.Expression,
				})
			}

			if license.Id != "" {
				*component.Licenses = append(*component.Licenses, cdx.LicenseChoice{
					License: &cdx.License{
						ID: license.Id,
					},
				})
			}
		}

		components = append(components, component)
		index[dep.Id] = len(components) - 1

		if !dep.IsSourcePackage {
			rootDependencies = append(rootDependencies, component.BOMRef)
		}
	}

	for _, dep := range deps.Tools {
		// skip if already added to BOM
		if _, found := index[dep.Id]; found {
			continue
		}

		purl := purlForPackage(dep)

		component := cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeApplication,
			Name:       dep.Name,
			Version:    dep.Version,
			PackageURL: purl,
			Scope:      cdx.ScopeExcluded,
			Properties: &[]cdx.Property{
				{
					Name:  "observer:build:role",
					Value: "tool",
				},
			},
		}

		var subComponents []cdx.Component
		for _, file := range dep.Files {
			fileHash, err := files.HashFileSha256(file)
			if err != nil {
				log.Error("failed to hash file", "file", file, "error", err)
				continue
			}
			subComponents = append(subComponents, cdx.Component{
				Type: cdx.ComponentTypeFile,
				Name: file,
				Hashes: &[]cdx.Hash{
					{
						Algorithm: "SHA-256",
						Value:     fileHash,
					},
				},
			})
		}

		if len(subComponents) > 0 {
			component.Components = &subComponents
		}

		components = append(components, component)
		index[dep.Id] = len(components) - 1

		if dep.IsSourcePackage {
			log.Error("cyclonedx: tools: build observation tool is unexpectedly transitive dependency", "tool", dep.Name)
		}

		rootDependencies = append(rootDependencies, component.BOMRef)
	}

	for _, dep := range deps.Transitive {
		// skip if already added to BOM
		if _, found := index[dep.Id]; found {
			continue
		}

		purl := purlForPackage(dep)

		component := cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       dep.Name,
			Version:    dep.Version,
			PackageURL: purl,
		}

		if dep.Scope == ScopeTool {
			component.Scope = cdx.ScopeExcluded
		}

		components = append(components, component)
		index[dep.Id] = len(components) - 1
	}

	// resolve code and package dependencies
	dependencies := map[string][]string{}
	for _, dep := range append(deps.Code, deps.Tools...) {
		component := components[index[dep.Id]]
		if len(dep.Dependencies) > 0 {
			for _, sourceDep := range dep.Dependencies {
				i, found := index[sourceDep]
				if !found {
					log.Warn("cyclonedx: dependencies: build observation package dependency not found", "dep", dep.Id, "depCount", len(dep.Dependencies), "sourceDep", sourceDep)
					continue
				}
				sourceComponent := components[i]
				dependencies[component.BOMRef] = append(dependencies[component.BOMRef], sourceComponent.BOMRef)
			}
		}
	}

	dependencies[bom.Metadata.Component.BOMRef] = rootDependencies

	ds := []cdx.Dependency{}
	for bomRef, refs := range dependencies {
		rc := deduplicate(refs)
		ds = append(ds, cdx.Dependency{
			Ref:          bomRef,
			Dependencies: &rc,
		})
	}

	bom.Components = &components
	bom.Dependencies = &ds

	return bom, nil
}

func purlForPackage(dep Package) string {
	if dep.OSFamily.PackageManager == ospkgs.PackageManagerDebian {
		var distro string

		switch dep.OSFamily.Name {
		case "debian":
			distro = fmt.Sprintf("%s-%s", dep.OSFamily.Distro, dep.OSFamily.Release)
		default:
			distro = "unknown"
		}

		return fmt.Sprintf("pkg:deb/debian/%s@%s?arch=%s&distro=%s", dep.Name, dep.Version, dep.Arch, distro)
	}

	if dep.OSFamily.PackageManager == ospkgs.PackageManagerRPM {
		distro := fmt.Sprintf("%s-%s", dep.OSFamily.Distro, dep.OSFamily.Release)
		return fmt.Sprintf("pkg:rpm/%s/%s@%s?arch=%s&distro=%s", dep.OSFamily.Name, dep.Name, dep.Version, dep.Arch, distro)
	}

	return fmt.Sprintf("pkg:generic/%s@%s", dep.Name, dep.Version)
}

func deduplicate[T comparable](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
