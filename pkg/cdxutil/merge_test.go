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
	}
	bom1.Components = &[]cdx.Component{
		{
			BOMRef:  "comp1",
			Name:    "lib1",
			Group:   "org1",
			Version: "1.0.0",
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

	bom2 := cdx.NewBOM()
	bom2.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef:  "root2",
			Name:    "app2",
			Group:   "org2",
			Version: "1.0.0",
			Type:    cdx.ComponentTypeApplication,
		},
	}
	bom2.Components = &[]cdx.Component{
		{
			BOMRef:  "comp3",
			Name:    "lib3",
			Group:   "org2",
			Version: "1.0.0",
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

	bom3 := cdx.NewBOM()
	bom3.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef:  "root3",
			Name:    "app3",
			Group:   "org3",
			Version: "1.0.0",
			Type:    cdx.ComponentTypeApplication,
		},
	}
	bom3.Components = &[]cdx.Component{
		{
			BOMRef:  "comp4",
			Name:    "lib4",
			Group:   "org3",
			Version: "1.0.0",
			Properties: &[]cdx.Property{
				{Name: "prop4", Value: "value4"},
			},
		},
	}

	// Merge the BOMs
	merged, err := mergeCycloneDX([]*cdx.BOM{bom1, bom2, bom3})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, merged)
	assert.NotNil(t, merged.Components)

	// Check if all unique components are present
	assert.Equal(t, 4, len(*merged.Components)) // comp1, comp2, comp3, comp4

	// Find comp1 and verify its properties were merged
	var comp1 *cdx.Component
	for _, comp := range *merged.Components {
		if comp.BOMRef == "comp1" {
			comp1 = &comp
			break
		}
	}

	assert.NotNil(t, comp1)
	assert.NotNil(t, comp1.Properties)
	assert.Equal(t, 2, len(*comp1.Properties)) // Should have both original and extra property
}
