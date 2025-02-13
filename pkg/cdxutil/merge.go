package cdxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/types"
	"slices"
)

// DestructiveMergeSBOMs merges multiple SBOMs into a single SBOM, inputs may be modified and should be considered invalid after this call
func DestructiveMergeSBOMs(config types.ScanConfig, results []*cdx.BOM) (*cdx.BOM, error) {
	// merge components and dependencies
	merged, err := mergeCycloneDX(results)
	if err != nil {
		return nil, err
	}

	// set metadata from config
	if config.Component.Type != "" {
		merged.Metadata.Component.Type = cdx.ComponentType(config.Component.Type)
	}
	if config.Component.Name != "" {
		merged.Metadata.Component.Name = config.Component.Name
	}
	if config.Component.Group != "" {
		merged.Metadata.Component.Group = config.Component.Group
	}
	if config.Component.Version != "" {
		merged.Metadata.Component.Version = config.Component.Version
	}
	if config.Component.Description != "" {
		merged.Metadata.Component.Description = config.Component.Description
	}
	if config.Component.License != "" {
		merged.Metadata.Component.Licenses = &cdx.Licenses{
			{
				License: &cdx.License{
					ID: config.Component.License,
				},
			},
		}
	}

	// author
	if config.Author.Name != "" {
		merged.Metadata.Authors = &[]cdx.OrganizationalContact{{
			Name: config.Author.Name,
		}}
	}

	if len(config.Author.Contacts) > 0 {
		if merged.Metadata.Authors == nil {
			merged.Metadata.Authors = &[]cdx.OrganizationalContact{}
		}

		for _, contact := range config.Author.Contacts {
			*merged.Metadata.Authors = append(*merged.Metadata.Authors, cdx.OrganizationalContact{
				Name:  contact.Name,
				Email: contact.Email,
				Phone: contact.Phone,
			})
		}
	}

	// supplier
	if config.Supplier.Name != "" {
		merged.Metadata.Supplier = &cdx.OrganizationalEntity{
			Name: config.Supplier.Name,
			URL:  &[]string{config.Supplier.URL},
		}
		if len(config.Supplier.Contacts) > 0 {
			merged.Metadata.Supplier.Contact = &[]cdx.OrganizationalContact{}
			for _, contact := range config.Supplier.Contacts {
				*merged.Metadata.Supplier.Contact = append(*merged.Metadata.Supplier.Contact, cdx.OrganizationalContact{
					Name:  contact.Name,
					Email: contact.Email,
					Phone: contact.Phone,
				})
			}
		}
	}

	// manufacturer
	if config.Manufacturer.Name != "" {
		merged.Metadata.Supplier = &cdx.OrganizationalEntity{
			Name: config.Manufacturer.Name,
			URL:  &[]string{config.Manufacturer.URL},
		}
		if len(config.Manufacturer.Contacts) > 0 {
			merged.Metadata.Supplier.Contact = &[]cdx.OrganizationalContact{}
			for _, contact := range config.Manufacturer.Contacts {
				*merged.Metadata.Supplier.Contact = append(*merged.Metadata.Supplier.Contact, cdx.OrganizationalContact{
					Name:  contact.Name,
					Email: contact.Email,
					Phone: contact.Phone,
				})
			}
		}
	}

	// add 'observer' tool if missing
	toolFound := false
	if merged.Metadata.Tools != nil && merged.Metadata.Tools.Components != nil {
		for _, tool := range *merged.Metadata.Tools.Components {
			if tool.Name == "observer" {
				toolFound = true
			}
		}
	}

	if !toolFound {
		if merged.Metadata.Tools == nil {
			merged.Metadata.Tools = &cdx.ToolsChoice{}
		}
		if merged.Metadata.Tools.Components == nil {
			merged.Metadata.Tools.Components = &[]cdx.Component{}
		}
		*merged.Metadata.Tools.Components = append(*merged.Metadata.Tools.Components, cdx.Component{
			Type:        cdx.ComponentTypeApplication,
			Name:        "observer",
			Description: "sbom.observer SBOM generator",
			//Publisher:   "Bitfront AB",
			Publisher: "https://sbom.observer",
			Version:   types.Version,
			ExternalReferences: &[]cdx.ExternalReference{
				{
					Type: cdx.ERTypeWebsite,
					URL:  "https://github.com/sbom-observer/observer-cli",
				},
			},
		})
	}

	// remove root component from components
	if merged.Metadata != nil && merged.Metadata.Component != nil {
		*merged.Components = slices.DeleteFunc(*merged.Components, func(component cdx.Component) bool {
			return component.Name == merged.Metadata.Component.Name && component.Group == merged.Metadata.Component.Group && component.Version == merged.Metadata.Component.Version
		})
	}

	return merged, nil
}

// mergeCycloneDX is very simplistic in that it only merges components and dependencies
func mergeCycloneDX(boms []*cdx.BOM) (*cdx.BOM, error) {
	// short-circuit if there's only one BOM
	if len(boms) == 1 {
		return boms[0], nil
	}

	merged := boms[0]

	// TODO: we might want to move the root component for each BOM and create a new uber root
	// move root component to components
	//if merged.Components == nil {
	//	merged.Components = &[]cdx.Component{}
	//}
	//*merged.Components = append(*merged.Components, *merged.Metadata.Component)

	// bomRef -> merged bomRef map
	components := map[string]string{}
	dependencies := map[string]*cdx.Dependency{}

	if merged.Components != nil {
		for _, component := range *merged.Components {
			components[component.BOMRef] = component.BOMRef
		}
	}

	if merged.Dependencies != nil {
		for _, dependency := range *merged.Dependencies {
			dependencies[dependency.Ref] = &dependency
		}
	}

	for _, bom := range boms[1:] {
		components[bom.Metadata.Component.BOMRef] = merged.Metadata.Component.BOMRef

		if merged.Components != nil {
			for _, component := range *bom.Components {
				_, found := components[component.BOMRef]

				if !found {
					components[component.BOMRef] = component.BOMRef
					*merged.Components = append(*merged.Components, component)
				}
			}
		}

		if bom.Dependencies != nil {
			for _, dependency := range *bom.Dependencies {
				bomRef := components[dependency.Ref]
				if bomRef == "" {
					log.Error("failed to find component for dependency ref", "dependency", dependency.Ref)
					continue
				}

				mergedDependency, found := dependencies[bomRef]
				if !found {
					dependency.Ref = bomRef
					if merged.Dependencies == nil {
						merged.Dependencies = &[]cdx.Dependency{}
					}
					*merged.Dependencies = append(*merged.Dependencies, dependency)
				} else {
					mergedDependencies := types.SliceSet[string](*mergedDependency.Dependencies)
					*mergedDependency.Dependencies = mergedDependencies.AddAll(*dependency.Dependencies)
				}
			}
		}

		// merge metadata tools
		if merged.Metadata.Tools == nil {
			merged.Metadata.Tools = &cdx.ToolsChoice{}
		}

		if merged.Metadata.Tools.Components == nil {
			merged.Metadata.Tools.Components = &[]cdx.Component{}
		}

		if bom.Metadata.Tools != nil && bom.Metadata.Tools.Components != nil {
			for _, tool := range *bom.Metadata.Tools.Components {
				found := false
				for _, existingTool := range *merged.Metadata.Tools.Components {
					if tool.Name == existingTool.Name && tool.Version == existingTool.Version {
						found = true
						break
					}
				}
				if !found {
					*merged.Metadata.Tools.Components = append(*merged.Metadata.Tools.Components, tool)
				}
			}
		}
	}

	return merged, nil
}
