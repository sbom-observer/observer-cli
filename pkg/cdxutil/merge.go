package cdxutil

import (
	"github.com/sbom-observer/observer-cli/pkg/ids"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/types"
)

// DestructiveMergeSBOMs merges multiple SBOMs into a single SBOM, inputs may be modified and should be considered invalid after this call
func DestructiveMergeSBOMs(config types.ScanConfig, results []*cdx.BOM, mergeRootComponent bool) (*cdx.BOM, error) {
	// merge components and dependencies
	merged, err := mergeCycloneDX(results, mergeRootComponent)
	if err != nil {
		return nil, err
	}

	// TODO: what do we do here?
	if merged == nil {
		merged = cdx.NewBOM()
		merged.Metadata = &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef: ids.NextUUID(),
				Type:   cdx.ComponentTypeApplication,
			},
		}
		merged.Components = &[]cdx.Component{}
	}

	// set metadata from config
	if config.Component.BOMRef != "" {
		merged.Metadata.Component.BOMRef = config.Component.BOMRef
	}

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
	if config.Component.Licenses != nil {
		merged.Metadata.Component.Licenses = config.Component.Licenses
	}
	if config.Component.Manufacturer != nil {
		merged.Metadata.Component.Manufacturer = config.Component.Manufacturer
	}
	if config.Component.Supplier != nil {
		merged.Metadata.Component.Supplier = config.Component.Supplier
	}

	// author
	if config.Author.Name != "" {
		merged.Metadata.Authors = &[]cdx.OrganizationalContact{
			config.Author,
		}
	}

	// supplier
	if config.Supplier.Name != "" {
		merged.Metadata.Supplier = &config.Supplier
	}

	// manufacturer
	if config.Manufacturer.Name != "" {
		merged.Metadata.Manufacturer = &config.Manufacturer
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
			Type: cdx.ComponentTypeApplication,
			Name: "observer",
			// Description: "sbom.observer SBOM generator",
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
	if merged.Metadata != nil && merged.Metadata.Component != nil && merged.Components != nil {
		*merged.Components = slices.DeleteFunc(*merged.Components, func(component cdx.Component) bool {
			return component.Name == merged.Metadata.Component.Name && component.Group == merged.Metadata.Component.Group && component.Version == merged.Metadata.Component.Version
		})
	}

	return merged, nil
}

// mergeCycloneDX is very simplistic in that it only merges components and dependencies
func mergeCycloneDX(boms []*cdx.BOM, mergeRootComponent bool) (*cdx.BOM, error) {
	if len(boms) == 0 {
		return nil, nil
	}

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

	if merged.Components == nil {
		merged.Components = &[]cdx.Component{}
	}

	if merged.Dependencies == nil {
		merged.Dependencies = &[]cdx.Dependency{}
	}

	for _, bom := range boms[1:] {
		if mergeRootComponent {
			// map the BOMRef of the root component to the *merged* BOMRef
			components[bom.Metadata.Component.BOMRef] = merged.Metadata.Component.BOMRef
		}

		if !mergeRootComponent {
			components[bom.Metadata.Component.BOMRef] = bom.Metadata.Component.BOMRef
			*merged.Components = append(*merged.Components, *bom.Metadata.Component)
			dep := dependencies[merged.Metadata.Component.BOMRef]
			if dep == nil {
				dep = &cdx.Dependency{
					Ref:          merged.Metadata.Component.BOMRef,
					Dependencies: &[]string{},
				}
				dependencies[merged.Metadata.Component.BOMRef] = dep
				*merged.Dependencies = append(*merged.Dependencies, *dep)
			}
			*dep.Dependencies = append(*dep.Dependencies, bom.Metadata.Component.BOMRef)
		}

		for _, component := range *bom.Components {
			_, found := components[component.BOMRef]

			// merge properties
			if found && component.Properties != nil {
				if idx := slices.IndexFunc(*merged.Components, func(c cdx.Component) bool {
					return c.BOMRef == component.BOMRef
				}); idx != -1 {
					existingComponent := (*merged.Components)[idx]
					if existingComponent.Properties == nil {
						existingComponent.Properties = &[]cdx.Property{}
					}
					for _, property := range *component.Properties {
						if !slices.ContainsFunc(*existingComponent.Properties, func(p cdx.Property) bool {
							return p.Name == property.Name
						}) {
							*existingComponent.Properties = append(*existingComponent.Properties, property)
						}
					}
				}
			}

			if !found {
				components[component.BOMRef] = component.BOMRef
				*merged.Components = append(*merged.Components, component)
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

	if len(*merged.Components) == 0 {
		merged.Components = nil
	}

	if len(*merged.Dependencies) == 0 {
		merged.Dependencies = nil
	}

	return merged, nil
}
