package mergex

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeMetadata_Nil(t *testing.T) {
	tests := []struct {
		name     string
		a        *cyclonedx.Metadata
		b        *cyclonedx.Metadata
		expected *cyclonedx.Metadata
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
			b: &cyclonedx.Metadata{
				Timestamp: "2023-01-01T00:00:00Z",
			},
			expected: &cyclonedx.Metadata{
				Timestamp: "2023-01-01T00:00:00Z",
			},
		},
		{
			name: "first has value, second nil",
			a: &cyclonedx.Metadata{
				Timestamp: "2023-01-01T00:00:00Z",
			},
			b: nil,
			expected: &cyclonedx.Metadata{
				Timestamp: "2023-01-01T00:00:00Z",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeMetadata(tt.a, tt.b)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected.Timestamp, result.Timestamp)
			}
		})
	}
}

func TestMergeMetadata_SimpleFields(t *testing.T) {
	t.Run("first input wins for non-empty fields", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Timestamp: "2023-01-01T00:00:00Z",
		}
		b := &cyclonedx.Metadata{
			Timestamp: "2023-02-01T00:00:00Z",
		}

		result := mergeMetadata(a, b)

		assert.Equal(t, "2023-01-01T00:00:00Z", result.Timestamp)
	})

	t.Run("second input fills empty fields", func(t *testing.T) {
		a := &cyclonedx.Metadata{}
		b := &cyclonedx.Metadata{
			Timestamp: "2023-02-01T00:00:00Z",
		}

		result := mergeMetadata(a, b)

		assert.Equal(t, "2023-02-01T00:00:00Z", result.Timestamp)
	})
}

func TestMergeMetadata_ComplexFields(t *testing.T) {
	t.Run("merge suppliers", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Supplier: &cyclonedx.OrganizationalEntity{
				Name: "Supplier A",
				URL:  &[]string{"http://a.com"},
			},
		}
		b := &cyclonedx.Metadata{
			Supplier: &cyclonedx.OrganizationalEntity{
				Name: "Supplier B",
				URL:  &[]string{"http://b.com"},
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Supplier)
		assert.Equal(t, "Supplier A", result.Supplier.Name) // First input wins
		assert.NotNil(t, result.Supplier.URL)
		assert.Equal(t, []string{"http://a.com", "http://b.com"}, *result.Supplier.URL) // Arrays merged
	})

	t.Run("fill nil complex fields from second input", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Timestamp: "2023-01-01T00:00:00Z",
			Supplier:  nil,
		}
		b := &cyclonedx.Metadata{
			Supplier: &cyclonedx.OrganizationalEntity{
				Name: "Supplier B",
			},
		}

		result := mergeMetadata(a, b)

		assert.Equal(t, "2023-01-01T00:00:00Z", result.Timestamp)
		assert.NotNil(t, result.Supplier)
		assert.Equal(t, "Supplier B", result.Supplier.Name)
	})

	t.Run("merge components", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Name:    "App A",
				Version: "1.0.0",
			},
		}
		b := &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Name:        "App B",
				Version:     "2.0.0",
				Description: "App B Description",
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Component)
		assert.Equal(t, "App A", result.Component.Name)       // First input wins
		assert.Equal(t, "1.0.0", result.Component.Version)   // First input wins
		assert.Equal(t, "App B Description", result.Component.Description) // Second fills empty
	})
}

func TestMergeMetadata_ArrayFields(t *testing.T) {
	t.Run("merge lifecycles", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Lifecycles: &[]cyclonedx.Lifecycle{
				{Name: "build", Phase: "build"},
			},
		}
		b := &cyclonedx.Metadata{
			Lifecycles: &[]cyclonedx.Lifecycle{
				{Name: "test", Phase: "test"},
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Lifecycles)
		assert.Len(t, *result.Lifecycles, 2)
		assert.Equal(t, "build", (*result.Lifecycles)[0].Name)
		assert.Equal(t, "test", (*result.Lifecycles)[1].Name)
	})

	t.Run("merge authors", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Authors: &[]cyclonedx.OrganizationalContact{
				{Name: "Author A"},
			},
		}
		b := &cyclonedx.Metadata{
			Authors: &[]cyclonedx.OrganizationalContact{
				{Name: "Author B"},
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Authors)
		assert.Len(t, *result.Authors, 2)
		assert.Equal(t, "Author A", (*result.Authors)[0].Name)
		assert.Equal(t, "Author B", (*result.Authors)[1].Name)
	})

	t.Run("merge properties by key", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "production"},
				{Name: "version", Value: "1.0.0"},
			},
		}
		b := &cyclonedx.Metadata{
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "staging"},    // duplicate key
				{Name: "owner", Value: "team-b"},
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Properties)
		assert.Len(t, *result.Properties, 3) // Only 3 unique keys

		// Convert to map for easier testing since order is not guaranteed
		propMap := make(map[string]string)
		for _, prop := range *result.Properties {
			propMap[prop.Name] = prop.Value
		}

		assert.Equal(t, "production", propMap["env"]) // First input wins
		assert.Equal(t, "1.0.0", propMap["version"])
		assert.Equal(t, "team-b", propMap["owner"])
	})

	t.Run("merge licenses", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Licenses: &cyclonedx.Licenses{
				{Expression: "MIT"},
			},
		}
		b := &cyclonedx.Metadata{
			Licenses: &cyclonedx.Licenses{
				{Expression: "Apache-2.0"},
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Licenses)
		assert.Len(t, *result.Licenses, 2)
		assert.Equal(t, "MIT", (*result.Licenses)[0].Expression)
		assert.Equal(t, "Apache-2.0", (*result.Licenses)[1].Expression)
	})
}

func TestMergeMetadata_ToolsChoice(t *testing.T) {
	t.Run("merge tools", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Tools: &cyclonedx.ToolsChoice{
				Tools: &[]cyclonedx.Tool{
					{Name: "Tool A", Version: "1.0.0"},
				},
			},
		}
		b := &cyclonedx.Metadata{
			Tools: &cyclonedx.ToolsChoice{
				Tools: &[]cyclonedx.Tool{
					{Name: "Tool B", Version: "2.0.0"},
				},
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Tools)
		assert.NotNil(t, result.Tools.Tools)
		assert.Len(t, *result.Tools.Tools, 2)
		assert.Equal(t, "Tool A", (*result.Tools.Tools)[0].Name)
		assert.Equal(t, "Tool B", (*result.Tools.Tools)[1].Name)
	})

	t.Run("merge tool components", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Tools: &cyclonedx.ToolsChoice{
				Components: &[]cyclonedx.Component{
					{Name: "Tool Component A"},
				},
			},
		}
		b := &cyclonedx.Metadata{
			Tools: &cyclonedx.ToolsChoice{
				Components: &[]cyclonedx.Component{
					{Name: "Tool Component B"},
				},
			},
		}

		result := mergeMetadata(a, b)

		assert.NotNil(t, result.Tools)
		assert.NotNil(t, result.Tools.Components)
		assert.Len(t, *result.Tools.Components, 2)
		assert.Equal(t, "Tool Component A", (*result.Tools.Components)[0].Name)
		assert.Equal(t, "Tool Component B", (*result.Tools.Components)[1].Name)
	})

	t.Run("fill nil tools from second input", func(t *testing.T) {
		a := &cyclonedx.Metadata{
			Timestamp: "2023-01-01T00:00:00Z",
			Tools:     nil,
		}
		b := &cyclonedx.Metadata{
			Tools: &cyclonedx.ToolsChoice{
				Tools: &[]cyclonedx.Tool{
					{Name: "Tool B"},
				},
			},
		}

		result := mergeMetadata(a, b)

		assert.Equal(t, "2023-01-01T00:00:00Z", result.Timestamp)
		assert.NotNil(t, result.Tools)
		assert.NotNil(t, result.Tools.Tools)
		assert.Len(t, *result.Tools.Tools, 1)
		assert.Equal(t, "Tool B", (*result.Tools.Tools)[0].Name)
	})
}

func TestMergeMetadata_Immutability(t *testing.T) {
	t.Run("original metadata are not modified", func(t *testing.T) {
		originalA := &cyclonedx.Metadata{
			Timestamp: "2023-01-01T00:00:00Z",
			Authors: &[]cyclonedx.OrganizationalContact{
				{Name: "Author A"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "production"},
			},
		}
		originalB := &cyclonedx.Metadata{
			Timestamp: "2023-02-01T00:00:00Z",
			Authors: &[]cyclonedx.OrganizationalContact{
				{Name: "Author B"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "owner", Value: "team-b"},
			},
		}

		// Create copies for comparison
		copyA := &cyclonedx.Metadata{
			Timestamp: originalA.Timestamp,
			Authors: &[]cyclonedx.OrganizationalContact{
				{Name: (*originalA.Authors)[0].Name},
			},
			Properties: &[]cyclonedx.Property{
				{Name: (*originalA.Properties)[0].Name, Value: (*originalA.Properties)[0].Value},
			},
		}
		copyB := &cyclonedx.Metadata{
			Timestamp: originalB.Timestamp,
			Authors: &[]cyclonedx.OrganizationalContact{
				{Name: (*originalB.Authors)[0].Name},
			},
			Properties: &[]cyclonedx.Property{
				{Name: (*originalB.Properties)[0].Name, Value: (*originalB.Properties)[0].Value},
			},
		}

		result := mergeMetadata(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, copyA.Timestamp, originalA.Timestamp)
		assert.Equal(t, (*copyA.Authors)[0].Name, (*originalA.Authors)[0].Name)
		assert.Equal(t, (*copyA.Properties)[0].Name, (*originalA.Properties)[0].Name)

		assert.Equal(t, copyB.Timestamp, originalB.Timestamp)
		assert.Equal(t, (*copyB.Authors)[0].Name, (*originalB.Authors)[0].Name)
		assert.Equal(t, (*copyB.Properties)[0].Name, (*originalB.Properties)[0].Name)

		// Verify result is different and contains expected values
		assert.Equal(t, "2023-01-01T00:00:00Z", result.Timestamp) // First input wins
		assert.Len(t, *result.Authors, 2)                         // Combined
		assert.Len(t, *result.Properties, 2)                      // Combined
	})
}

func TestMergeToolsChoice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeToolsChoice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("merge all tool types", func(t *testing.T) {
		a := &cyclonedx.ToolsChoice{
			Tools: &[]cyclonedx.Tool{
				{Name: "Legacy Tool A"},
			},
			Components: &[]cyclonedx.Component{
				{Name: "Component Tool A"},
			},
			Services: &[]cyclonedx.Service{
				{Name: "Service Tool A"},
			},
		}
		b := &cyclonedx.ToolsChoice{
			Tools: &[]cyclonedx.Tool{
				{Name: "Legacy Tool B"},
			},
			Components: &[]cyclonedx.Component{
				{Name: "Component Tool B"},
			},
			Services: &[]cyclonedx.Service{
				{Name: "Service Tool B"},
			},
		}

		result := mergeToolsChoice(a, b)

		assert.NotNil(t, result.Tools)
		assert.Len(t, *result.Tools, 2)
		assert.Equal(t, "Legacy Tool A", (*result.Tools)[0].Name)
		assert.Equal(t, "Legacy Tool B", (*result.Tools)[1].Name)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 2)
		assert.Equal(t, "Component Tool A", (*result.Components)[0].Name)
		assert.Equal(t, "Component Tool B", (*result.Components)[1].Name)

		assert.NotNil(t, result.Services)
		assert.Len(t, *result.Services, 2)
		assert.Equal(t, "Service Tool A", (*result.Services)[0].Name)
		assert.Equal(t, "Service Tool B", (*result.Services)[1].Name)
	})
}