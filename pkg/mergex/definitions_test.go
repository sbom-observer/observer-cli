package mergex

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeDefinitions(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeDefinitions(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-b",
					Name:        "Standard B",
					Version:     "1.0",
					Description: "Description B",
				},
			},
		}

		result := mergeDefinitions(nil, b)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Standards)
		assert.Len(t, *result.Standards, 1)
		assert.Equal(t, "standard-b", (*result.Standards)[0].BOMRef)
		assert.Equal(t, "Standard B", (*result.Standards)[0].Name)
		assert.Equal(t, "1.0", (*result.Standards)[0].Version)
		assert.Equal(t, "Description B", (*result.Standards)[0].Description)
	})

	t.Run("first has values, second nil", func(t *testing.T) {
		a := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-a",
					Name:        "Standard A",
					Version:     "2.0",
					Description: "Description A",
				},
			},
		}

		result := mergeDefinitions(a, nil)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Standards)
		assert.Len(t, *result.Standards, 1)
		assert.Equal(t, "standard-a", (*result.Standards)[0].BOMRef)
		assert.Equal(t, "Standard A", (*result.Standards)[0].Name)
		assert.Equal(t, "2.0", (*result.Standards)[0].Version)
		assert.Equal(t, "Description A", (*result.Standards)[0].Description)
	})

	t.Run("merge definitions with different standards", func(t *testing.T) {
		a := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-a",
					Name:        "Standard A",
					Version:     "1.0",
					Description: "Description A",
				},
			},
		}
		b := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-b",
					Name:        "Standard B",
					Version:     "2.0",
					Description: "Description B",
				},
			},
		}

		result := mergeDefinitions(a, b)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Standards)
		assert.Len(t, *result.Standards, 2)

		// Convert to map for easier testing since order is not guaranteed
		standardMap := make(map[string]cyclonedx.StandardDefinition)
		for _, std := range *result.Standards {
			standardMap[std.BOMRef] = std
		}

		assert.Equal(t, "Standard A", standardMap["standard-a"].Name)
		assert.Equal(t, "1.0", standardMap["standard-a"].Version)
		assert.Equal(t, "Description A", standardMap["standard-a"].Description)

		assert.Equal(t, "Standard B", standardMap["standard-b"].Name)
		assert.Equal(t, "2.0", standardMap["standard-b"].Version)
		assert.Equal(t, "Description B", standardMap["standard-b"].Description)
	})

	t.Run("merge definitions with overlapping standards", func(t *testing.T) {
		a := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-a",
					Name:        "Standard A",
					Version:     "1.0",
					Description: "Original description",
					Owner:       "Owner A",
					Requirements: &[]cyclonedx.StandardRequirement{
						{BOMRef: "req-1", Identifier: "REQ-001"},
					},
				},
			},
		}
		b := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-a", // Same BOMRef as first
					Name:        "Standard A Updated", // Should not override
					Version:     "2.0", // Should not override
					Description: "Updated description", // Should not override
					Owner:       "Owner B", // Should not override
					Requirements: &[]cyclonedx.StandardRequirement{
						{BOMRef: "req-2", Identifier: "REQ-002"},
					},
				},
			},
		}

		result := mergeDefinitions(a, b)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Standards)
		assert.Len(t, *result.Standards, 1) // One merged standard

		std := (*result.Standards)[0]
		assert.Equal(t, "standard-a", std.BOMRef)
		assert.Equal(t, "Standard A", std.Name) // First input wins
		assert.Equal(t, "1.0", std.Version) // First input wins
		assert.Equal(t, "Original description", std.Description) // First input wins
		assert.Equal(t, "Owner A", std.Owner) // First input wins

		// Requirements should be concatenated
		assert.NotNil(t, std.Requirements)
		assert.Len(t, *std.Requirements, 2)
		assert.Equal(t, "req-1", (*std.Requirements)[0].BOMRef)
		assert.Equal(t, "REQ-001", (*std.Requirements)[0].Identifier)
		assert.Equal(t, "req-2", (*std.Requirements)[1].BOMRef)
		assert.Equal(t, "REQ-002", (*std.Requirements)[1].Identifier)
	})

	t.Run("merge definitions with empty standards", func(t *testing.T) {
		a := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{},
		}
		b := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{},
		}

		result := mergeDefinitions(a, b)

		assert.NotNil(t, result)
		assert.Nil(t, result.Standards) // Empty arrays result in nil
	})
}

func TestMergeStandardDefinition(t *testing.T) {
	t.Run("merge standards with same BOMRef", func(t *testing.T) {
		a := cyclonedx.StandardDefinition{
			BOMRef:      "standard-a",
			Name:        "Standard A",
			Version:     "1.0",
			Description: "Original description",
			Owner:       "Owner A",
			Requirements: &[]cyclonedx.StandardRequirement{
				{BOMRef: "req-1", Identifier: "REQ-001"},
			},
			ExternalReferences: &[]cyclonedx.ExternalReference{
				{URL: "https://example.com/a", Type: "website"},
			},
		}
		b := cyclonedx.StandardDefinition{
			BOMRef:      "standard-a",
			Name:        "Standard B", // Should not override first
			Version:     "2.0", // Should not override first
			Description: "Updated description", // Should not override first
			Owner:       "Owner B", // Should not override first
			Requirements: &[]cyclonedx.StandardRequirement{
				{BOMRef: "req-2", Identifier: "REQ-002"},
			},
			ExternalReferences: &[]cyclonedx.ExternalReference{
				{URL: "https://example.com/b", Type: "vcs"},
			},
		}

		result := mergeStandardDefinition(a, b)

		assert.Equal(t, "standard-a", result.BOMRef)
		assert.Equal(t, "Standard A", result.Name) // First input wins
		assert.Equal(t, "1.0", result.Version) // First input wins
		assert.Equal(t, "Original description", result.Description) // First input wins
		assert.Equal(t, "Owner A", result.Owner) // First input wins

		// Arrays should be concatenated
		assert.NotNil(t, result.Requirements)
		assert.Len(t, *result.Requirements, 2)
		assert.Equal(t, "req-1", (*result.Requirements)[0].BOMRef)
		assert.Equal(t, "req-2", (*result.Requirements)[1].BOMRef)

		assert.NotNil(t, result.ExternalReferences)
		assert.Len(t, *result.ExternalReferences, 2)
		assert.Equal(t, "https://example.com/a", (*result.ExternalReferences)[0].URL)
		assert.Equal(t, "https://example.com/b", (*result.ExternalReferences)[1].URL)
	})

	t.Run("merge standards with empty fields", func(t *testing.T) {
		a := cyclonedx.StandardDefinition{
			BOMRef: "standard-a",
			Name:   "Standard A",
			// Version empty - should be filled from b
			// Description empty - should be filled from b
			Requirements: &[]cyclonedx.StandardRequirement{
				{BOMRef: "req-1"},
			},
		}
		b := cyclonedx.StandardDefinition{
			BOMRef:      "standard-a",
			Name:        "Standard B",
			Version:     "2.0", // Should fill empty field
			Description: "Filled from second", // Should fill empty field
			Owner:       "Owner B", // Should fill empty field
			Requirements: nil,
		}

		result := mergeStandardDefinition(a, b)

		assert.Equal(t, "standard-a", result.BOMRef)
		assert.Equal(t, "Standard A", result.Name) // First input wins
		assert.Equal(t, "2.0", result.Version) // Filled from second
		assert.Equal(t, "Filled from second", result.Description) // Filled from second
		assert.Equal(t, "Owner B", result.Owner) // Filled from second

		// Requirements from first should be preserved
		assert.NotNil(t, result.Requirements)
		assert.Len(t, *result.Requirements, 1)
		assert.Equal(t, "req-1", (*result.Requirements)[0].BOMRef)
	})

	t.Run("merge standards with nil arrays", func(t *testing.T) {
		a := cyclonedx.StandardDefinition{
			BOMRef:       "standard-a",
			Name:         "Standard A",
			Requirements: &[]cyclonedx.StandardRequirement{{BOMRef: "req-1"}},
			Levels:       nil,
		}
		b := cyclonedx.StandardDefinition{
			BOMRef:       "standard-a",
			Name:         "Standard B",
			Requirements: nil,
			Levels:       &[]cyclonedx.StandardLevel{{BOMRef: "level-1"}},
		}

		result := mergeStandardDefinition(a, b)

		assert.Equal(t, "standard-a", result.BOMRef)
		assert.Equal(t, "Standard A", result.Name) // First input wins

		// Requirements from first should be preserved
		assert.NotNil(t, result.Requirements)
		assert.Len(t, *result.Requirements, 1)
		assert.Equal(t, "req-1", (*result.Requirements)[0].BOMRef)

		// Levels from second should be included
		assert.NotNil(t, result.Levels)
		assert.Len(t, *result.Levels, 1)
		assert.Equal(t, "level-1", (*result.Levels)[0].BOMRef)
	})
}

func TestMergeStandardDefinitionSlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeStandardDefinitionSlice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.StandardDefinition{
			{
				BOMRef:      "standard-b",
				Name:        "Standard B",
				Version:     "1.0",
				Description: "Description B",
			},
		}

		result := mergeStandardDefinitionSlice(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "standard-b", (*result)[0].BOMRef)
		assert.Equal(t, "Standard B", (*result)[0].Name)
	})

	t.Run("merge slices with no overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.StandardDefinition{
			{
				BOMRef:      "standard-a",
				Name:        "Standard A",
				Version:     "1.0",
				Description: "Description A",
			},
		}
		b := &[]cyclonedx.StandardDefinition{
			{
				BOMRef:      "standard-b",
				Name:        "Standard B",
				Version:     "2.0",
				Description: "Description B",
			},
		}

		result := mergeStandardDefinitionSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Convert to map for easier testing since order is not guaranteed
		standardMap := make(map[string]cyclonedx.StandardDefinition)
		for _, std := range *result {
			standardMap[std.BOMRef] = std
		}

		assert.Equal(t, "Standard A", standardMap["standard-a"].Name)
		assert.Equal(t, "1.0", standardMap["standard-a"].Version)
		assert.Equal(t, "Standard B", standardMap["standard-b"].Name)
		assert.Equal(t, "2.0", standardMap["standard-b"].Version)
	})

	t.Run("merge slices with overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.StandardDefinition{
			{
				BOMRef:      "standard-a",
				Name:        "Standard A",
				Version:     "1.0",
				Description: "Original description",
				Requirements: &[]cyclonedx.StandardRequirement{
					{BOMRef: "req-1", Identifier: "REQ-001"},
				},
			},
			{
				BOMRef:      "standard-b",
				Name:        "Standard B",
				Version:     "1.0",
			},
		}
		b := &[]cyclonedx.StandardDefinition{
			{
				BOMRef:      "standard-a", // Same BOMRef as first
				Name:        "Standard A Updated", // Should not override
				Version:     "2.0", // Should not override
				Description: "Updated description", // Should not override
				Requirements: &[]cyclonedx.StandardRequirement{
					{BOMRef: "req-2", Identifier: "REQ-002"},
				},
			},
			{
				BOMRef:      "standard-c",
				Name:        "Standard C",
				Version:     "1.0",
			},
		}

		result := mergeStandardDefinitionSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // standard-a merged, standard-b and standard-c separate

		// Convert to map for easier testing since order is not guaranteed
		standardMap := make(map[string]cyclonedx.StandardDefinition)
		for _, std := range *result {
			standardMap[std.BOMRef] = std
		}

		// standard-a should have merged fields and first input precedence
		assert.Equal(t, "Standard A", standardMap["standard-a"].Name) // First input wins
		assert.Equal(t, "1.0", standardMap["standard-a"].Version) // First input wins
		assert.Equal(t, "Original description", standardMap["standard-a"].Description) // First input wins

		// Requirements should be concatenated
		assert.NotNil(t, standardMap["standard-a"].Requirements)
		assert.Len(t, *standardMap["standard-a"].Requirements, 2)

		// standard-b should remain unchanged
		assert.Equal(t, "Standard B", standardMap["standard-b"].Name)
		assert.Equal(t, "1.0", standardMap["standard-b"].Version)

		// standard-c should be added as-is
		assert.Equal(t, "Standard C", standardMap["standard-c"].Name)
		assert.Equal(t, "1.0", standardMap["standard-c"].Version)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.StandardDefinition{}
		b := &[]cyclonedx.StandardDefinition{}

		result := mergeStandardDefinitionSlice(a, b)

		assert.Nil(t, result)
	})
}

func TestMergeStandardArrays(t *testing.T) {
	t.Run("merge requirement slices", func(t *testing.T) {
		a := &[]cyclonedx.StandardRequirement{
			{BOMRef: "req-1", Identifier: "REQ-001"},
			{BOMRef: "req-2", Identifier: "REQ-002"},
		}
		b := &[]cyclonedx.StandardRequirement{
			{BOMRef: "req-3", Identifier: "REQ-003"},
		}

		result := mergeStandardRequirementSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3)
		assert.Equal(t, "req-1", (*result)[0].BOMRef)
		assert.Equal(t, "REQ-001", (*result)[0].Identifier)
		assert.Equal(t, "req-2", (*result)[1].BOMRef)
		assert.Equal(t, "REQ-002", (*result)[1].Identifier)
		assert.Equal(t, "req-3", (*result)[2].BOMRef)
		assert.Equal(t, "REQ-003", (*result)[2].Identifier)
	})

	t.Run("merge level slices", func(t *testing.T) {
		a := &[]cyclonedx.StandardLevel{
			{BOMRef: "level-1"},
		}
		b := &[]cyclonedx.StandardLevel{
			{BOMRef: "level-2"},
			{BOMRef: "level-3"},
		}

		result := mergeStandardLevelSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3)
		assert.Equal(t, "level-1", (*result)[0].BOMRef)
		assert.Equal(t, "level-2", (*result)[1].BOMRef)
		assert.Equal(t, "level-3", (*result)[2].BOMRef)
	})

	t.Run("merge with nil slices", func(t *testing.T) {
		a := &[]cyclonedx.StandardRequirement{
			{BOMRef: "req-1"},
		}

		result1 := mergeStandardRequirementSlice(a, nil)
		assert.NotNil(t, result1)
		assert.Len(t, *result1, 1)
		assert.Equal(t, "req-1", (*result1)[0].BOMRef)

		result2 := mergeStandardRequirementSlice(nil, a)
		assert.NotNil(t, result2)
		assert.Len(t, *result2, 1)
		assert.Equal(t, "req-1", (*result2)[0].BOMRef)

		result3 := mergeStandardRequirementSlice(nil, nil)
		assert.Nil(t, result3)
	})
}

func TestMergeDefinitions_Immutability(t *testing.T) {
	t.Run("original definitions are not modified", func(t *testing.T) {
		originalA := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-a",
					Name:        "Standard A",
					Version:     "1.0",
					Description: "Original description",
					Requirements: &[]cyclonedx.StandardRequirement{
						{BOMRef: "req-1", Identifier: "REQ-001"},
					},
				},
			},
		}
		originalB := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      "standard-a", // Same BOMRef for merging
					Name:        "Standard A Updated",
					Version:     "2.0",
					Description: "Updated description",
					Requirements: &[]cyclonedx.StandardRequirement{
						{BOMRef: "req-2", Identifier: "REQ-002"},
					},
				},
			},
		}

		// Create copies for comparison
		copyA := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      (*originalA.Standards)[0].BOMRef,
					Name:        (*originalA.Standards)[0].Name,
					Version:     (*originalA.Standards)[0].Version,
					Description: (*originalA.Standards)[0].Description,
					Requirements: &[]cyclonedx.StandardRequirement{
						{BOMRef: (*(*originalA.Standards)[0].Requirements)[0].BOMRef, Identifier: (*(*originalA.Standards)[0].Requirements)[0].Identifier},
					},
				},
			},
		}
		copyB := &cyclonedx.Definitions{
			Standards: &[]cyclonedx.StandardDefinition{
				{
					BOMRef:      (*originalB.Standards)[0].BOMRef,
					Name:        (*originalB.Standards)[0].Name,
					Version:     (*originalB.Standards)[0].Version,
					Description: (*originalB.Standards)[0].Description,
					Requirements: &[]cyclonedx.StandardRequirement{
						{BOMRef: (*(*originalB.Standards)[0].Requirements)[0].BOMRef, Identifier: (*(*originalB.Standards)[0].Requirements)[0].Identifier},
					},
				},
			},
		}

		result := mergeDefinitions(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, (*copyA.Standards)[0].BOMRef, (*originalA.Standards)[0].BOMRef)
		assert.Equal(t, (*copyA.Standards)[0].Name, (*originalA.Standards)[0].Name)
		assert.Equal(t, (*copyA.Standards)[0].Version, (*originalA.Standards)[0].Version)
		assert.Equal(t, (*copyA.Standards)[0].Description, (*originalA.Standards)[0].Description)
		assert.Equal(t, (*(*copyA.Standards)[0].Requirements)[0].BOMRef, (*(*originalA.Standards)[0].Requirements)[0].BOMRef)

		assert.Equal(t, (*copyB.Standards)[0].BOMRef, (*originalB.Standards)[0].BOMRef)
		assert.Equal(t, (*copyB.Standards)[0].Name, (*originalB.Standards)[0].Name)
		assert.Equal(t, (*copyB.Standards)[0].Version, (*originalB.Standards)[0].Version)
		assert.Equal(t, (*copyB.Standards)[0].Description, (*originalB.Standards)[0].Description)
		assert.Equal(t, (*(*copyB.Standards)[0].Requirements)[0].BOMRef, (*(*originalB.Standards)[0].Requirements)[0].BOMRef)

		// Verify result is merged correctly
		assert.NotNil(t, result)
		assert.NotNil(t, result.Standards)
		assert.Len(t, *result.Standards, 1) // One merged standard
		assert.Equal(t, "standard-a", (*result.Standards)[0].BOMRef)
		assert.Equal(t, "Standard A", (*result.Standards)[0].Name) // First input wins

		// Both requirement arrays should be merged in result
		assert.NotNil(t, (*result.Standards)[0].Requirements)
		assert.Len(t, *(*result.Standards)[0].Requirements, 2) // Both requirements combined
	})
}