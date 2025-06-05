package cdxutil

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeCycloneDX(t *testing.T) {
	// Create three test BOMs
	bom1 := cdx.NewBOM()
	bom1.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef:  "root1",
			Name:    "app1",
			Group:   "org1",
			Version: "1.0.0",
			Type:    cdx.ComponentTypeApplication,
		},
		Supplier: &cdx.OrganizationalEntity{
			Name: "Supplier 1",
			URL:  &[]string{"https://supplier1.com"},
		},
		Manufacturer: &cdx.OrganizationalEntity{
			Name: "Manufacturer 1",
			URL:  &[]string{"https://manufacturer1.com"},
		},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Name:    "tool1",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeApplication,
				},
				{
					Name:    "shared-tool",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeApplication,
				},
			},
		},
	}
	bom1.Components = &[]cdx.Component{
		{
			BOMRef:  "comp1",
			Name:    "lib1",
			Group:   "org1",
			Version: "1.0.0",
			Supplier: &cdx.OrganizationalEntity{
				Name: "Component Supplier 1",
				URL:  &[]string{"https://comp-supplier1.com"},
			},
			Manufacturer: &cdx.OrganizationalEntity{
				Name: "Component Manufacturer 1",
				URL:  &[]string{"https://comp-manufacturer1.com"},
			},
			Properties: &[]cdx.Property{
				{Name: "prop1", Value: "value1"},
			},
		},
		{
			BOMRef:  "comp2",
			Name:    "lib2",
			Group:   "org1",
			Version: "1.0.0",
			Properties: &[]cdx.Property{
				{Name: "prop2", Value: "value2"},
			},
		},
	}
	bom1.Dependencies = &[]cdx.Dependency{
		{
			Ref:          "root1",
			Dependencies: &[]string{"comp1", "comp2"},
		},
		{
			Ref:          "comp1",
			Dependencies: &[]string{},
		},
	}

	bom2 := cdx.NewBOM()
	bom2.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef:  "root2",
			Name:    "app2",
			Group:   "org2",
			Version: "1.0.0",
			Type:    cdx.ComponentTypeApplication,
		},
		Supplier: &cdx.OrganizationalEntity{
			Name: "Supplier 2",
			URL:  &[]string{"https://supplier2.com"},
		},
		Manufacturer: &cdx.OrganizationalEntity{
			Name: "Manufacturer 2",
			URL:  &[]string{"https://manufacturer2.com"},
		},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Name:    "tool2",
					Version: "2.0.0",
					Type:    cdx.ComponentTypeApplication,
				},
				{
					Name:    "shared-tool",
					Version: "1.0.0", // Same as bom1, should not duplicate
					Type:    cdx.ComponentTypeApplication,
				},
				{
					Name:    "shared-tool",
					Version: "2.0.0", // Different version, should be added
					Type:    cdx.ComponentTypeApplication,
				},
			},
		},
	}
	bom2.Components = &[]cdx.Component{
		{
			BOMRef:  "comp3",
			Name:    "lib3",
			Group:   "org2",
			Version: "1.0.0",
			Supplier: &cdx.OrganizationalEntity{
				Name: "Component Supplier 3",
				URL:  &[]string{"https://comp-supplier3.com"},
			},
			Properties: &[]cdx.Property{
				{Name: "prop3", Value: "value3"},
			},
		},
		// Add comp1 again but with additional property
		{
			BOMRef:  "comp1",
			Name:    "lib1",
			Group:   "org1",
			Version: "1.0.0",
			Properties: &[]cdx.Property{
				{Name: "prop1", Value: "value1"},
				{Name: "prop1-extra", Value: "value-extra"},
			},
		},
	}
	bom2.Dependencies = &[]cdx.Dependency{
		{
			Ref:          "root2",
			Dependencies: &[]string{"comp3", "comp1"},
		},
		{
			Ref:          "comp1",
			Dependencies: &[]string{"comp3"}, // comp1 now depends on comp3
		},
	}

	bom3 := cdx.NewBOM()
	bom3.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef:  "root3",
			Name:    "app3",
			Group:   "org3",
			Version: "1.0.0",
			Type:    cdx.ComponentTypeApplication,
		},
		Supplier: &cdx.OrganizationalEntity{
			Name: "Supplier 3",
			URL:  &[]string{"https://supplier3.com"},
		},
		Manufacturer: &cdx.OrganizationalEntity{
			Name: "Manufacturer 3",
			URL:  &[]string{"https://manufacturer3.com"},
		},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Name:    "tool3",
					Version: "3.0.0",
					Type:    cdx.ComponentTypeApplication,
				},
			},
		},
	}
	bom3.Components = &[]cdx.Component{
		{
			BOMRef:  "comp4",
			Name:    "lib4",
			Group:   "org3",
			Version: "1.0.0",
			Manufacturer: &cdx.OrganizationalEntity{
				Name: "Component Manufacturer 4",
				URL:  &[]string{"https://comp-manufacturer4.com"},
			},
			Properties: &[]cdx.Property{
				{Name: "prop4", Value: "value4"},
			},
		},
	}
	bom3.Dependencies = &[]cdx.Dependency{
		{
			Ref:          "root3",
			Dependencies: &[]string{"comp4"},
		},
	}

	// Merge the BOMs
	merged, err := mergeCycloneDX([]*cdx.BOM{bom1, bom2, bom3})

	// Basic assertions
	assert.NoError(t, err)
	assert.NotNil(t, merged)
	assert.NotNil(t, merged.Components)
	assert.NotNil(t, merged.Dependencies)
	assert.NotNil(t, merged.Metadata)
	assert.NotNil(t, merged.Metadata.Tools)
	assert.NotNil(t, merged.Metadata.Tools.Components)

	// Check if all unique components are present
	assert.Equal(t, 4, len(*merged.Components)) // comp1, comp2, comp3, comp4

	// Verify each component exists with correct properties
	components := make(map[string]cdx.Component)
	for _, comp := range *merged.Components {
		components[comp.BOMRef] = comp
	}

	// Check comp1 - should have merged properties
	comp1, exists := components["comp1"]
	assert.True(t, exists)
	assert.Equal(t, "lib1", comp1.Name)
	assert.Equal(t, "org1", comp1.Group)
	assert.Equal(t, "1.0.0", comp1.Version)
	assert.NotNil(t, comp1.Properties)
	assert.Equal(t, 2, len(*comp1.Properties)) // Should have both original and extra property

	// Verify comp1 supplier and manufacturer come from first occurrence
	assert.NotNil(t, comp1.Supplier)
	assert.Equal(t, "Component Supplier 1", comp1.Supplier.Name)
	assert.NotNil(t, comp1.Supplier.URL)
	assert.Equal(t, "https://comp-supplier1.com", (*comp1.Supplier.URL)[0])

	assert.NotNil(t, comp1.Manufacturer)
	assert.Equal(t, "Component Manufacturer 1", comp1.Manufacturer.Name)
	assert.NotNil(t, comp1.Manufacturer.URL)
	assert.Equal(t, "https://comp-manufacturer1.com", (*comp1.Manufacturer.URL)[0])

	// Check properties exist
	propNames := make(map[string]string)
	for _, prop := range *comp1.Properties {
		propNames[prop.Name] = prop.Value
	}
	assert.Equal(t, "value1", propNames["prop1"])
	assert.Equal(t, "value-extra", propNames["prop1-extra"])

	// Check comp2
	comp2, exists := components["comp2"]
	assert.True(t, exists)
	assert.Equal(t, "lib2", comp2.Name)
	assert.Equal(t, "org1", comp2.Group)
	assert.Equal(t, "1.0.0", comp2.Version)
	assert.NotNil(t, comp2.Properties)
	assert.Equal(t, 1, len(*comp2.Properties))
	assert.Equal(t, "prop2", (*comp2.Properties)[0].Name)
	assert.Equal(t, "value2", (*comp2.Properties)[0].Value)

	// Verify comp2 has no supplier or manufacturer
	assert.Nil(t, comp2.Supplier)
	assert.Nil(t, comp2.Manufacturer)

	// Check comp3
	comp3, exists := components["comp3"]
	assert.True(t, exists)
	assert.Equal(t, "lib3", comp3.Name)
	assert.Equal(t, "org2", comp3.Group)
	assert.Equal(t, "1.0.0", comp3.Version)
	assert.NotNil(t, comp3.Properties)
	assert.Equal(t, 1, len(*comp3.Properties))
	assert.Equal(t, "prop3", (*comp3.Properties)[0].Name)
	assert.Equal(t, "value3", (*comp3.Properties)[0].Value)

	// Verify comp3 supplier
	assert.NotNil(t, comp3.Supplier)
	assert.Equal(t, "Component Supplier 3", comp3.Supplier.Name)
	assert.NotNil(t, comp3.Supplier.URL)
	assert.Equal(t, "https://comp-supplier3.com", (*comp3.Supplier.URL)[0])
	assert.Nil(t, comp3.Manufacturer)

	// Check comp4
	comp4, exists := components["comp4"]
	assert.True(t, exists)
	assert.Equal(t, "lib4", comp4.Name)
	assert.Equal(t, "org3", comp4.Group)
	assert.Equal(t, "1.0.0", comp4.Version)
	assert.NotNil(t, comp4.Properties)
	assert.Equal(t, 1, len(*comp4.Properties))
	assert.Equal(t, "prop4", (*comp4.Properties)[0].Name)
	assert.Equal(t, "value4", (*comp4.Properties)[0].Value)

	// Verify comp4 manufacturer
	assert.NotNil(t, comp4.Manufacturer)
	assert.Equal(t, "Component Manufacturer 4", comp4.Manufacturer.Name)
	assert.NotNil(t, comp4.Manufacturer.URL)
	assert.Equal(t, "https://comp-manufacturer4.com", (*comp4.Manufacturer.URL)[0])
	assert.Nil(t, comp4.Supplier)

	// Check dependencies are merged correctly
	dependencies := make(map[string]*cdx.Dependency)
	for _, dep := range *merged.Dependencies {
		dependencies[dep.Ref] = &dep
	}

	// Root dependency should point to root1 (from first BOM) and have all dependencies
	rootDep, exists := dependencies["root1"]
	assert.True(t, exists)
	assert.NotNil(t, rootDep.Dependencies)
	// Should contain comp1, comp2 from bom1 and comp3 from bom2 (mapped to root1)
	assert.Contains(t, *rootDep.Dependencies, "comp1")
	assert.Contains(t, *rootDep.Dependencies, "comp2")
	assert.Contains(t, *rootDep.Dependencies, "comp3")
	assert.Contains(t, *rootDep.Dependencies, "comp4")

	// comp1 dependency should be merged (empty from bom1, comp3 from bom2)
	comp1Dep, exists := dependencies["comp1"]
	assert.True(t, exists)
	assert.NotNil(t, comp1Dep.Dependencies)
	assert.Contains(t, *comp1Dep.Dependencies, "comp3")

	// Check metadata tools are merged correctly
	assert.Equal(t, 5, len(*merged.Metadata.Tools.Components)) // tool1, shared-tool(1.0.0), tool2, shared-tool(2.0.0), tool3

	toolMap := make(map[string]cdx.Component)
	for _, tool := range *merged.Metadata.Tools.Components {
		key := tool.Name + "@" + tool.Version
		toolMap[key] = tool
	}

	// Check all expected tools exist
	_, exists = toolMap["tool1@1.0.0"]
	assert.True(t, exists)
	_, exists = toolMap["tool2@2.0.0"]
	assert.True(t, exists)
	_, exists = toolMap["tool3@3.0.0"]
	assert.True(t, exists)
	_, exists = toolMap["shared-tool@1.0.0"]
	assert.True(t, exists)
	_, exists = toolMap["shared-tool@2.0.0"]
	assert.True(t, exists)

	// Verify metadata comes from first BOM
	assert.Equal(t, "root1", merged.Metadata.Component.BOMRef)
	assert.Equal(t, "app1", merged.Metadata.Component.Name)
	assert.Equal(t, "org1", merged.Metadata.Component.Group)
	assert.Equal(t, "1.0.0", merged.Metadata.Component.Version)
	assert.Equal(t, cdx.ComponentTypeApplication, merged.Metadata.Component.Type)

	// Verify supplier and manufacturer come from first BOM
	assert.NotNil(t, merged.Metadata.Supplier)
	assert.Equal(t, "Supplier 1", merged.Metadata.Supplier.Name)
	assert.NotNil(t, merged.Metadata.Supplier.URL)
	assert.Equal(t, "https://supplier1.com", (*merged.Metadata.Supplier.URL)[0])

	assert.NotNil(t, merged.Metadata.Manufacturer)
	assert.Equal(t, "Manufacturer 1", merged.Metadata.Manufacturer.Name)
	assert.NotNil(t, merged.Metadata.Manufacturer.URL)
	assert.Equal(t, "https://manufacturer1.com", (*merged.Metadata.Manufacturer.URL)[0])
}
