package mergex

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeComponent_SimpleFields(t *testing.T) {
	tests := []struct {
		name     string
		a        cyclonedx.Component
		b        cyclonedx.Component
		expected cyclonedx.Component
	}{
		{
			name: "first input wins for non-empty fields",
			a: cyclonedx.Component{
				Name:        "ComponentA",
				Version:     "1.0.0",
				Description: "Description A",
			},
			b: cyclonedx.Component{
				Name:        "ComponentB",
				Version:     "2.0.0",
				Description: "Description B",
			},
			expected: cyclonedx.Component{
				Name:        "ComponentA",
				Version:     "1.0.0",
				Description: "Description A",
			},
		},
		{
			name: "second input fills empty fields",
			a: cyclonedx.Component{
				Name: "ComponentA",
			},
			b: cyclonedx.Component{
				Name:        "ComponentB",
				Version:     "2.0.0",
				Description: "Description B",
			},
			expected: cyclonedx.Component{
				Name:        "ComponentA",
				Version:     "2.0.0",
				Description: "Description B",
			},
		},
		{
			name:     "empty inputs",
			a:        cyclonedx.Component{},
			b:        cyclonedx.Component{},
			expected: cyclonedx.Component{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeComponent(tt.a, tt.b)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Version, result.Version)
			assert.Equal(t, tt.expected.Description, result.Description)
		})
	}
}

func TestMergeComponent_ArrayFields(t *testing.T) {
	t.Run("merge string arrays", func(t *testing.T) {
		a := cyclonedx.Component{
			OmniborID: &[]string{"id1", "id2"},
		}
		b := cyclonedx.Component{
			OmniborID: &[]string{"id3", "id4"},
		}

		result := MergeComponent(a, b)

		assert.NotNil(t, result.OmniborID)
		assert.Equal(t, []string{"id1", "id2", "id3", "id4"}, *result.OmniborID)
	})

	t.Run("merge hash arrays", func(t *testing.T) {
		a := cyclonedx.Component{
			Hashes: &[]cyclonedx.Hash{
				{Algorithm: "SHA-256", Value: "abc123"},
			},
		}
		b := cyclonedx.Component{
			Hashes: &[]cyclonedx.Hash{
				{Algorithm: "SHA-1", Value: "def456"},
			},
		}

		result := MergeComponent(a, b)

		assert.NotNil(t, result.Hashes)
		assert.Len(t, *result.Hashes, 2)
		assert.Equal(t, "SHA-256", string((*result.Hashes)[0].Algorithm))
		assert.Equal(t, "abc123", (*result.Hashes)[0].Value)
		assert.Equal(t, "SHA-1", string((*result.Hashes)[1].Algorithm))
		assert.Equal(t, "def456", (*result.Hashes)[1].Value)
	})

	t.Run("merge properties arrays", func(t *testing.T) {
		a := cyclonedx.Component{
			Properties: &[]cyclonedx.Property{
				{Name: "prop1", Value: "value1"},
			},
		}
		b := cyclonedx.Component{
			Properties: &[]cyclonedx.Property{
				{Name: "prop2", Value: "value2"},
			},
		}

		result := MergeComponent(a, b)

		assert.NotNil(t, result.Properties)
		assert.Len(t, *result.Properties, 2)

		// Convert to map for easier testing since order is not guaranteed
		propMap := make(map[string]string)
		for _, prop := range *result.Properties {
			propMap[prop.Name] = prop.Value
		}

		assert.Equal(t, "value1", propMap["prop1"])
		assert.Equal(t, "value2", propMap["prop2"])
	})
}

func TestMergeComponent_NilArrays(t *testing.T) {
	t.Run("one nil array", func(t *testing.T) {
		a := cyclonedx.Component{
			OmniborID: &[]string{"id1"},
		}
		b := cyclonedx.Component{
			OmniborID: nil,
		}

		result := MergeComponent(a, b)

		assert.NotNil(t, result.OmniborID)
		assert.Equal(t, []string{"id1"}, *result.OmniborID)
	})

	t.Run("both nil arrays", func(t *testing.T) {
		a := cyclonedx.Component{OmniborID: nil}
		b := cyclonedx.Component{OmniborID: nil}

		result := MergeComponent(a, b)

		assert.Nil(t, result.OmniborID)
	})
}

func TestMergeComponent_NestedComponents(t *testing.T) {
	t.Run("merge nested components", func(t *testing.T) {
		a := cyclonedx.Component{
			Name: "Parent A",
			Components: &[]cyclonedx.Component{
				{Name: "Child A1"},
			},
		}
		b := cyclonedx.Component{
			Name: "Parent B",
			Components: &[]cyclonedx.Component{
				{Name: "Child B1"},
			},
		}

		result := MergeComponent(a, b)

		assert.Equal(t, "Parent A", result.Name) // First input wins
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 2)
		assert.Equal(t, "Child A1", (*result.Components)[0].Name)
		assert.Equal(t, "Child B1", (*result.Components)[1].Name)
	})
}

func TestMergeOrganizationalEntity(t *testing.T) {
	tests := []struct {
		name     string
		a        *cyclonedx.OrganizationalEntity
		b        *cyclonedx.OrganizationalEntity
		expected *cyclonedx.OrganizationalEntity
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name: "first nil, second has value",
			a:    nil,
			b: &cyclonedx.OrganizationalEntity{
				Name: "Org B",
			},
			expected: &cyclonedx.OrganizationalEntity{
				Name: "Org B",
			},
		},
		{
			name: "first has value, second nil",
			a: &cyclonedx.OrganizationalEntity{
				Name: "Org A",
			},
			b: nil,
			expected: &cyclonedx.OrganizationalEntity{
				Name: "Org A",
			},
		},
		{
			name: "first input wins for non-empty fields",
			a: &cyclonedx.OrganizationalEntity{
				Name:   "Org A",
				BOMRef: "ref-a",
			},
			b: &cyclonedx.OrganizationalEntity{
				Name:   "Org B",
				BOMRef: "ref-b",
			},
			expected: &cyclonedx.OrganizationalEntity{
				Name:   "Org A",
				BOMRef: "ref-a",
			},
		},
		{
			name: "fill empty fields from second input",
			a: &cyclonedx.OrganizationalEntity{
				Name: "Org A",
			},
			b: &cyclonedx.OrganizationalEntity{
				Name:   "Org B",
				BOMRef: "ref-b",
			},
			expected: &cyclonedx.OrganizationalEntity{
				Name:   "Org A",
				BOMRef: "ref-b",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeOrganizationalEntity(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeOrganizationalEntity_Arrays(t *testing.T) {
	t.Run("merge URL arrays", func(t *testing.T) {
		a := &cyclonedx.OrganizationalEntity{
			Name: "Org A",
			URL:  &[]string{"http://a.com"},
		}
		b := &cyclonedx.OrganizationalEntity{
			Name: "Org B",
			URL:  &[]string{"http://b.com"},
		}

		result := mergeOrganizationalEntity(a, b)

		assert.Equal(t, "Org A", result.Name) // First input wins
		assert.NotNil(t, result.URL)
		assert.Equal(t, []string{"http://a.com", "http://b.com"}, *result.URL)
	})

	t.Run("merge contact arrays", func(t *testing.T) {
		a := &cyclonedx.OrganizationalEntity{
			Name: "Org A",
			Contact: &[]cyclonedx.OrganizationalContact{
				{Name: "Contact A"},
			},
		}
		b := &cyclonedx.OrganizationalEntity{
			Name: "Org B",
			Contact: &[]cyclonedx.OrganizationalContact{
				{Name: "Contact B"},
			},
		}

		result := mergeOrganizationalEntity(a, b)

		assert.Equal(t, "Org A", result.Name)
		assert.NotNil(t, result.Contact)
		assert.Len(t, *result.Contact, 2)
		assert.Equal(t, "Contact A", (*result.Contact)[0].Name)
		assert.Equal(t, "Contact B", (*result.Contact)[1].Name)
	})
}

func TestMergeSWID(t *testing.T) {
	tests := []struct {
		name     string
		a        *cyclonedx.SWID
		b        *cyclonedx.SWID
		expected *cyclonedx.SWID
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name: "first nil, second has value",
			a:    nil,
			b: &cyclonedx.SWID{
				TagID: "tag-b",
				Name:  "SWID B",
			},
			expected: &cyclonedx.SWID{
				TagID: "tag-b",
				Name:  "SWID B",
			},
		},
		{
			name: "first input wins for non-empty fields",
			a: &cyclonedx.SWID{
				TagID:   "tag-a",
				Name:    "SWID A",
				Version: "1.0.0",
			},
			b: &cyclonedx.SWID{
				TagID:   "tag-b",
				Name:    "SWID B",
				Version: "2.0.0",
			},
			expected: &cyclonedx.SWID{
				TagID:   "tag-a",
				Name:    "SWID A",
				Version: "1.0.0",
			},
		},
		{
			name: "fill empty fields from second input",
			a: &cyclonedx.SWID{
				TagID: "tag-a",
			},
			b: &cyclonedx.SWID{
				TagID:   "tag-b",
				Name:    "SWID B",
				Version: "2.0.0",
			},
			expected: &cyclonedx.SWID{
				TagID:   "tag-a",
				Name:    "SWID B",
				Version: "2.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeSWID(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeLicenses(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeLicenses(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has value", func(t *testing.T) {
		b := &cyclonedx.Licenses{
			{Expression: "MIT"},
		}

		result := mergeLicenses(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "MIT", (*result)[0].Expression)
	})

	t.Run("merge both licenses", func(t *testing.T) {
		a := &cyclonedx.Licenses{
			{Expression: "MIT"},
		}
		b := &cyclonedx.Licenses{
			{Expression: "Apache-2.0"},
		}

		result := mergeLicenses(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)
		assert.Equal(t, "MIT", (*result)[0].Expression)
		assert.Equal(t, "Apache-2.0", (*result)[1].Expression)
	})
}

func TestMergeStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		a        *[]string
		b        *[]string
		expected *[]string
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name:     "first nil, second has values",
			a:        nil,
			b:        &[]string{"b1", "b2"},
			expected: &[]string{"b1", "b2"},
		},
		{
			name:     "first has values, second nil",
			a:        &[]string{"a1", "a2"},
			b:        nil,
			expected: &[]string{"a1", "a2"},
		},
		{
			name:     "both have values",
			a:        &[]string{"a1", "a2"},
			b:        &[]string{"b1", "b2"},
			expected: &[]string{"a1", "a2", "b1", "b2"},
		},
		{
			name:     "empty slices",
			a:        &[]string{},
			b:        &[]string{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeStringSlice(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeComponent_Immutability(t *testing.T) {
	t.Run("original components are not modified", func(t *testing.T) {
		originalA := cyclonedx.Component{
			Name:      "Original A",
			Version:   "1.0.0",
			OmniborID: &[]string{"id1"},
		}
		originalB := cyclonedx.Component{
			Name:      "Original B",
			Version:   "2.0.0",
			OmniborID: &[]string{"id2"},
		}

		// Make copies to compare against later
		copyA := originalA
		copyB := originalB
		if originalA.OmniborID != nil {
			copyASlice := make([]string, len(*originalA.OmniborID))
			copy(copyASlice, *originalA.OmniborID)
			copyA.OmniborID = &copyASlice
		}
		if originalB.OmniborID != nil {
			copyBSlice := make([]string, len(*originalB.OmniborID))
			copy(copyBSlice, *originalB.OmniborID)
			copyB.OmniborID = &copyBSlice
		}

		result := MergeComponent(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, copyA, originalA)
		assert.Equal(t, copyB, originalB)

		// Verify result is different and contains expected values
		assert.Equal(t, "Original A", result.Name)
		assert.Equal(t, "1.0.0", result.Version)
		assert.NotNil(t, result.OmniborID)
		assert.Equal(t, []string{"id1", "id2"}, *result.OmniborID)
	})
}

func TestMergeComponent_ComplexTypes(t *testing.T) {
	t.Run("merge suppliers", func(t *testing.T) {
		a := cyclonedx.Component{
			Name: "Component A",
			Supplier: &cyclonedx.OrganizationalEntity{
				Name: "Supplier A",
				URL:  &[]string{"http://a.com"},
			},
		}
		b := cyclonedx.Component{
			Name: "Component B",
			Supplier: &cyclonedx.OrganizationalEntity{
				Name: "Supplier B",
				URL:  &[]string{"http://b.com"},
			},
		}

		result := MergeComponent(a, b)

		assert.Equal(t, "Component A", result.Name)
		assert.NotNil(t, result.Supplier)
		assert.Equal(t, "Supplier A", result.Supplier.Name) // First input wins
		assert.NotNil(t, result.Supplier.URL)
		assert.Equal(t, []string{"http://a.com", "http://b.com"}, *result.Supplier.URL) // Arrays merged
	})

	t.Run("merge with nil supplier in first input", func(t *testing.T) {
		a := cyclonedx.Component{
			Name:     "Component A",
			Supplier: nil,
		}
		b := cyclonedx.Component{
			Name: "Component B",
			Supplier: &cyclonedx.OrganizationalEntity{
				Name: "Supplier B",
			},
		}

		result := MergeComponent(a, b)

		assert.Equal(t, "Component A", result.Name)
		assert.NotNil(t, result.Supplier)
		assert.Equal(t, "Supplier B", result.Supplier.Name)
	})
}

func TestMergePropertySlice(t *testing.T) {
	t.Run("merge properties by key - no duplicates", func(t *testing.T) {
		a := &[]cyclonedx.Property{
			{Name: "env", Value: "production"},
			{Name: "version", Value: "1.0.0"},
		}
		b := &[]cyclonedx.Property{
			{Name: "owner", Value: "team-a"},
			{Name: "region", Value: "us-east"},
		}

		result := mergePropertySlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 4)

		// Convert to map for easier testing since order is not guaranteed
		propMap := make(map[string]string)
		for _, prop := range *result {
			propMap[prop.Name] = prop.Value
		}

		assert.Equal(t, "production", propMap["env"])
		assert.Equal(t, "1.0.0", propMap["version"])
		assert.Equal(t, "team-a", propMap["owner"])
		assert.Equal(t, "us-east", propMap["region"])
	})

	t.Run("merge properties by key - first input wins for duplicates", func(t *testing.T) {
		a := &[]cyclonedx.Property{
			{Name: "env", Value: "production"},
			{Name: "version", Value: "1.0.0"},
		}
		b := &[]cyclonedx.Property{
			{Name: "env", Value: "staging"}, // duplicate key - should be overridden by a
			{Name: "owner", Value: "team-b"},
		}

		result := mergePropertySlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // Only 3 unique keys

		// Convert to map for easier testing since order is not guaranteed
		propMap := make(map[string]string)
		for _, prop := range *result {
			propMap[prop.Name] = prop.Value
		}

		assert.Equal(t, "production", propMap["env"]) // First input wins
		assert.Equal(t, "1.0.0", propMap["version"])
		assert.Equal(t, "team-b", propMap["owner"])
	})

	t.Run("merge properties - nil handling", func(t *testing.T) {
		a := &[]cyclonedx.Property{
			{Name: "env", Value: "production"},
		}

		result := mergePropertySlice(a, nil)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "env", (*result)[0].Name)
		assert.Equal(t, "production", (*result)[0].Value)
	})

	t.Run("merge properties - both nil", func(t *testing.T) {
		result := mergePropertySlice(nil, nil)
		assert.Nil(t, result)
	})
}

func TestMergeComponentSlice(t *testing.T) {
	t.Run("merge components with same BOMRef", func(t *testing.T) {
		a := &[]cyclonedx.Component{
			{
				BOMRef:      "component-1",
				Name:        "Component A",
				Version:     "1.0.0",
				Description: "Description A",
				Type:        cyclonedx.ComponentTypeApplication,
			},
			{
				BOMRef:  "component-2",
				Name:    "Component B",
				Version: "1.0.0",
			},
		}

		b := &[]cyclonedx.Component{
			{
				BOMRef:    "component-1",                  // Same BOMRef - should merge
				Name:      "Component A Different",        // Different name
				Version:   "1.0.0",                        // Same version
				Copyright: "Copyright B",                  // New field from B
				Type:      cyclonedx.ComponentTypeLibrary, // Different type
			},
			{
				BOMRef:  "component-3",
				Name:    "Component C",
				Version: "1.0.0",
			},
		}

		result := mergeComponentSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // component-1 merged, component-2 and component-3 separate

		// Convert to map for easier testing since order is not guaranteed
		componentMap := make(map[string]cyclonedx.Component)
		for _, comp := range *result {
			componentMap[comp.BOMRef] = comp
		}

		// component-1 should have merged with first input winning for non-empty fields
		assert.Equal(t, "Component A", componentMap["component-1"].Name)                      // First input wins
		assert.Equal(t, "1.0.0", componentMap["component-1"].Version)                         // Same in both
		assert.Equal(t, "Description A", componentMap["component-1"].Description)             // First input wins
		assert.Equal(t, cyclonedx.ComponentTypeApplication, componentMap["component-1"].Type) // First input wins
		assert.Equal(t, "Copyright B", componentMap["component-1"].Copyright)                 // Second input fills empty

		assert.Equal(t, "Component B", componentMap["component-2"].Name)
		assert.Equal(t, "Component C", componentMap["component-3"].Name)
	})

	t.Run("merge components without BOMRef", func(t *testing.T) {
		a := &[]cyclonedx.Component{
			{
				Name:        "Component A",
				Version:     "1.0.0",
				PackageURL:  "pkg:npm/component-a@1.0.0",
				Description: "Description A",
			},
		}

		b := &[]cyclonedx.Component{
			{
				Name:       "Component A",               // Same name
				Version:    "1.0.0",                     // Same version
				PackageURL: "pkg:npm/component-a@1.0.0", // Same PURL - should merge
				Copyright:  "Copyright B",               // New field
			},
			{
				Name:       "Component B",
				Version:    "2.0.0",
				PackageURL: "pkg:npm/component-b@2.0.0",
			},
		}

		result := mergeComponentSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2) // First component merged, second component separate

		// Find the merged component (it will have the key from name|version|packageURL)
		var mergedComp *cyclonedx.Component
		var otherComp *cyclonedx.Component
		for _, comp := range *result {
			if comp.Name == "Component A" && comp.Version == "1.0.0" {
				mergedComp = &comp
			} else if comp.Name == "Component B" {
				otherComp = &comp
			}
		}

		assert.NotNil(t, mergedComp, "Should find merged Component A")
		assert.NotNil(t, otherComp, "Should find Component B")

		// Verify merge worked correctly
		assert.Equal(t, "Component A", mergedComp.Name)
		assert.Equal(t, "1.0.0", mergedComp.Version)
		assert.Equal(t, "pkg:npm/component-a@1.0.0", mergedComp.PackageURL)
		assert.Equal(t, "Description A", mergedComp.Description) // First input wins
		assert.Equal(t, "Copyright B", mergedComp.Copyright)     // Second input fills empty

		assert.Equal(t, "Component B", otherComp.Name)
		assert.Equal(t, "2.0.0", otherComp.Version)
	})

	t.Run("no duplicates with unique BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Component{
			{BOMRef: "component-1", Name: "Component A"},
			{BOMRef: "component-2", Name: "Component B"},
		}

		b := &[]cyclonedx.Component{
			{BOMRef: "component-3", Name: "Component C"},
			{BOMRef: "component-4", Name: "Component D"},
		}

		result := mergeComponentSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 4) // All components should be included

		// Verify all components are present
		componentNames := make([]string, 0, 4)
		for _, comp := range *result {
			componentNames = append(componentNames, comp.Name)
		}
		assert.Contains(t, componentNames, "Component A")
		assert.Contains(t, componentNames, "Component B")
		assert.Contains(t, componentNames, "Component C")
		assert.Contains(t, componentNames, "Component D")
	})

	t.Run("nil slices", func(t *testing.T) {
		result := mergeComponentSlice(nil, nil)
		assert.Nil(t, result)

		a := &[]cyclonedx.Component{{BOMRef: "comp-1", Name: "Component A"}}
		result = mergeComponentSlice(a, nil)
		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "Component A", (*result)[0].Name)

		result = mergeComponentSlice(nil, a)
		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "Component A", (*result)[0].Name)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.Component{}
		b := &[]cyclonedx.Component{}

		result := mergeComponentSlice(a, b)
		assert.Nil(t, result)
	})

	t.Run("mixed BOMRef and non-BOMRef components", func(t *testing.T) {
		a := &[]cyclonedx.Component{
			{
				BOMRef:  "component-with-bomref",
				Name:    "Component With BOMRef",
				Version: "1.0.0",
			},
			{
				// No BOMRef
				Name:       "Component Without BOMRef",
				Version:    "2.0.0",
				PackageURL: "pkg:npm/no-bomref@2.0.0",
			},
		}

		b := &[]cyclonedx.Component{
			{
				BOMRef:    "component-with-bomref", // Same BOMRef - should merge
				Name:      "Component With BOMRef",
				Version:   "1.0.0",
				Copyright: "Copyright from B",
			},
			{
				// No BOMRef, same name|version|purl - should merge
				Name:        "Component Without BOMRef",
				Version:     "2.0.0",
				PackageURL:  "pkg:npm/no-bomref@2.0.0",
				Description: "Description from B",
			},
			{
				BOMRef:  "new-component",
				Name:    "New Component",
				Version: "3.0.0",
			},
		}

		result := mergeComponentSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // Two merged, one new

		// Convert to map for easier verification
		componentMap := make(map[string]cyclonedx.Component)
		noBomRefComps := make([]cyclonedx.Component, 0)

		for _, comp := range *result {
			if comp.BOMRef != "" {
				componentMap[comp.BOMRef] = comp
			} else {
				noBomRefComps = append(noBomRefComps, comp)
			}
		}

		// Verify BOMRef component merged correctly
		assert.Equal(t, "Component With BOMRef", componentMap["component-with-bomref"].Name)
		assert.Equal(t, "Copyright from B", componentMap["component-with-bomref"].Copyright)

		assert.Equal(t, "New Component", componentMap["new-component"].Name)

		// Verify non-BOMRef component merged correctly
		assert.Len(t, noBomRefComps, 1)
		assert.Equal(t, "Component Without BOMRef", noBomRefComps[0].Name)
		assert.Equal(t, "Description from B", noBomRefComps[0].Description)
	})
}

func TestMergeComponentSlice_Immutability(t *testing.T) {
	t.Run("original slices are not modified", func(t *testing.T) {
		originalA := &[]cyclonedx.Component{
			{BOMRef: "comp-1", Name: "Component A", Version: "1.0.0"},
		}
		originalB := &[]cyclonedx.Component{
			{BOMRef: "comp-1", Name: "Component A", Copyright: "Copyright B"},
		}

		// Create copies for comparison
		copyA := make([]cyclonedx.Component, len(*originalA))
		copy(copyA, *originalA)
		copyB := make([]cyclonedx.Component, len(*originalB))
		copy(copyB, *originalB)

		result := mergeComponentSlice(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, copyA[0].Name, (*originalA)[0].Name)
		assert.Equal(t, copyA[0].Version, (*originalA)[0].Version)
		assert.Equal(t, "", (*originalA)[0].Copyright) // Should remain empty

		assert.Equal(t, copyB[0].Name, (*originalB)[0].Name)
		assert.Equal(t, "", (*originalB)[0].Version) // Should remain empty
		assert.Equal(t, copyB[0].Copyright, (*originalB)[0].Copyright)

		// Verify result has merged content
		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "Component A", (*result)[0].Name)
		assert.Equal(t, "1.0.0", (*result)[0].Version)
		assert.Equal(t, "Copyright B", (*result)[0].Copyright)
	})
}
