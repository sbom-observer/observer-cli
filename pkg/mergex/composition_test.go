package mergex

import (
	"sort"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeComposition(t *testing.T) {
	t.Run("merge compositions with same BOMRef", func(t *testing.T) {
		a := cyclonedx.Composition{
			BOMRef:    "comp-a",
			Aggregate: cyclonedx.CompositionAggregateComplete,
			Assemblies: &[]cyclonedx.BOMReference{
				"assembly1", "assembly2",
			},
			Dependencies: &[]cyclonedx.BOMReference{
				"dep1", "dep2",
			},
		}
		b := cyclonedx.Composition{
			BOMRef:    "comp-a",
			Aggregate: cyclonedx.CompositionAggregateIncomplete, // Should not override first
			Assemblies: &[]cyclonedx.BOMReference{
				"assembly2", "assembly3", // assembly2 is duplicate
			},
			Dependencies: &[]cyclonedx.BOMReference{
				"dep2", "dep3", // dep2 is duplicate
			},
			Vulnerabilities: &[]cyclonedx.BOMReference{
				"vuln1",
			},
		}

		result := mergeComposition(a, b)

		assert.Equal(t, "comp-a", result.BOMRef)
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, result.Aggregate) // First input wins

		// Check assemblies are merged and deduplicated
		assert.NotNil(t, result.Assemblies)
		assemblies := make([]string, len(*result.Assemblies))
		for i, ref := range *result.Assemblies {
			assemblies[i] = string(ref)
		}
		sort.Strings(assemblies)
		assert.Len(t, assemblies, 3)
		assert.Equal(t, []string{"assembly1", "assembly2", "assembly3"}, assemblies)

		// Check dependencies are merged and deduplicated
		assert.NotNil(t, result.Dependencies)
		deps := make([]string, len(*result.Dependencies))
		for i, ref := range *result.Dependencies {
			deps[i] = string(ref)
		}
		sort.Strings(deps)
		assert.Len(t, deps, 3)
		assert.Equal(t, []string{"dep1", "dep2", "dep3"}, deps)

		// Check vulnerabilities from b are included
		assert.NotNil(t, result.Vulnerabilities)
		assert.Len(t, *result.Vulnerabilities, 1)
		assert.Equal(t, cyclonedx.BOMReference("vuln1"), (*result.Vulnerabilities)[0])
	})

	t.Run("merge compositions with nil arrays", func(t *testing.T) {
		a := cyclonedx.Composition{
			BOMRef:    "comp-a",
			Aggregate: cyclonedx.CompositionAggregateComplete,
			Assemblies: &[]cyclonedx.BOMReference{
				"assembly1",
			},
			Dependencies: nil,
		}
		b := cyclonedx.Composition{
			BOMRef:       "comp-a",
			Aggregate:    cyclonedx.CompositionAggregateIncomplete,
			Assemblies:   nil,
			Dependencies: &[]cyclonedx.BOMReference{"dep1"},
		}

		result := mergeComposition(a, b)

		assert.Equal(t, "comp-a", result.BOMRef)
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, result.Aggregate)

		// Assemblies from a should be preserved
		assert.NotNil(t, result.Assemblies)
		assert.Equal(t, []cyclonedx.BOMReference{"assembly1"}, *result.Assemblies)

		// Dependencies from b should be included
		assert.NotNil(t, result.Dependencies)
		assert.Equal(t, []cyclonedx.BOMReference{"dep1"}, *result.Dependencies)

		// Vulnerabilities should be nil
		assert.Nil(t, result.Vulnerabilities)
	})

	t.Run("merge compositions with empty arrays", func(t *testing.T) {
		a := cyclonedx.Composition{
			BOMRef:     "comp-a",
			Aggregate:  cyclonedx.CompositionAggregateComplete,
			Assemblies: &[]cyclonedx.BOMReference{},
		}
		b := cyclonedx.Composition{
			BOMRef:     "comp-a",
			Aggregate:  cyclonedx.CompositionAggregateIncomplete,
			Assemblies: &[]cyclonedx.BOMReference{},
		}

		result := mergeComposition(a, b)

		assert.Equal(t, "comp-a", result.BOMRef)
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, result.Aggregate)
		assert.Nil(t, result.Assemblies) // Empty arrays result in nil
	})
}

func TestMergeCompositionSlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeCompositionSlice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.Composition{
			{
				BOMRef:    "comp-b",
				Aggregate: cyclonedx.CompositionAggregateComplete,
				Assemblies: &[]cyclonedx.BOMReference{
					"assembly1",
				},
			},
		}

		result := mergeCompositionSlice(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "comp-b", (*result)[0].BOMRef)
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, (*result)[0].Aggregate)
		assert.Equal(t, []cyclonedx.BOMReference{"assembly1"}, *(*result)[0].Assemblies)
	})

	t.Run("merge slices with no overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Composition{
			{
				BOMRef:    "comp-a",
				Aggregate: cyclonedx.CompositionAggregateComplete,
				Assemblies: &[]cyclonedx.BOMReference{
					"assembly1", "assembly2",
				},
			},
		}
		b := &[]cyclonedx.Composition{
			{
				BOMRef:    "comp-b",
				Aggregate: cyclonedx.CompositionAggregateIncomplete,
				Dependencies: &[]cyclonedx.BOMReference{
					"dep1", "dep2",
				},
			},
		}

		result := mergeCompositionSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Convert to map for easier testing since order is not guaranteed
		compMap := make(map[string]cyclonedx.Composition)
		for _, comp := range *result {
			compMap[comp.BOMRef] = comp
		}

		assert.Equal(t, cyclonedx.CompositionAggregateComplete, compMap["comp-a"].Aggregate)
		assert.Equal(t, []cyclonedx.BOMReference{"assembly1", "assembly2"}, *compMap["comp-a"].Assemblies)

		assert.Equal(t, cyclonedx.CompositionAggregateIncomplete, compMap["comp-b"].Aggregate)
		assert.Equal(t, []cyclonedx.BOMReference{"dep1", "dep2"}, *compMap["comp-b"].Dependencies)
	})

	t.Run("merge slices with overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Composition{
			{
				BOMRef:    "comp-a",
				Aggregate: cyclonedx.CompositionAggregateComplete,
				Assemblies: &[]cyclonedx.BOMReference{
					"assembly1", "assembly2",
				},
			},
			{
				BOMRef:    "comp-b",
				Aggregate: cyclonedx.CompositionAggregateIncomplete,
				Dependencies: &[]cyclonedx.BOMReference{
					"dep1",
				},
			},
		}
		b := &[]cyclonedx.Composition{
			{
				BOMRef:    "comp-a", // Same BOMRef as first
				Aggregate: cyclonedx.CompositionAggregateIncomplete, // Should not override
				Assemblies: &[]cyclonedx.BOMReference{
					"assembly2", "assembly3", // assembly2 is duplicate
				},
				Dependencies: &[]cyclonedx.BOMReference{
					"dep2",
				},
			},
			{
				BOMRef:    "comp-c",
				Aggregate: cyclonedx.CompositionAggregateComplete,
				Vulnerabilities: &[]cyclonedx.BOMReference{
					"vuln1",
				},
			},
		}

		result := mergeCompositionSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // comp-a merged, comp-b and comp-c separate

		// Convert to map for easier testing since order is not guaranteed
		compMap := make(map[string]cyclonedx.Composition)
		for _, comp := range *result {
			compMap[comp.BOMRef] = comp
		}

		// comp-a should have merged arrays and first input aggregate
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, compMap["comp-a"].Aggregate)
		assemblies := make([]string, len(*compMap["comp-a"].Assemblies))
		for i, ref := range *compMap["comp-a"].Assemblies {
			assemblies[i] = string(ref)
		}
		sort.Strings(assemblies)
		assert.Equal(t, []string{"assembly1", "assembly2", "assembly3"}, assemblies)
		assert.Equal(t, []cyclonedx.BOMReference{"dep2"}, *compMap["comp-a"].Dependencies)

		// comp-b should remain unchanged
		assert.Equal(t, cyclonedx.CompositionAggregateIncomplete, compMap["comp-b"].Aggregate)
		assert.Equal(t, []cyclonedx.BOMReference{"dep1"}, *compMap["comp-b"].Dependencies)

		// comp-c should be added as-is
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, compMap["comp-c"].Aggregate)
		assert.Equal(t, []cyclonedx.BOMReference{"vuln1"}, *compMap["comp-c"].Vulnerabilities)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.Composition{}
		b := &[]cyclonedx.Composition{}

		result := mergeCompositionSlice(a, b)

		assert.Nil(t, result)
	})
}

func TestMergeBOMReferenceSlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeBOMReferenceSlice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("no duplicates", func(t *testing.T) {
		a := &[]cyclonedx.BOMReference{"ref1", "ref2"}
		b := &[]cyclonedx.BOMReference{"ref3", "ref4"}

		result := mergeBOMReferenceSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 4)

		// Sort for predictable testing
		refs := make([]string, len(*result))
		for i, ref := range *result {
			refs[i] = string(ref)
		}
		sort.Strings(refs)
		assert.Equal(t, []string{"ref1", "ref2", "ref3", "ref4"}, refs)
	})

	t.Run("with duplicates", func(t *testing.T) {
		a := &[]cyclonedx.BOMReference{"ref1", "ref2", "ref3"}
		b := &[]cyclonedx.BOMReference{"ref2", "ref3", "ref4"}

		result := mergeBOMReferenceSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 4) // ref2 and ref3 are deduplicated

		// Sort for predictable testing
		refs := make([]string, len(*result))
		for i, ref := range *result {
			refs[i] = string(ref)
		}
		sort.Strings(refs)
		assert.Equal(t, []string{"ref1", "ref2", "ref3", "ref4"}, refs)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.BOMReference{"ref1", "ref2"}

		result := mergeBOMReferenceSlice(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Sort for predictable testing
		refs := make([]string, len(*result))
		for i, ref := range *result {
			refs[i] = string(ref)
		}
		sort.Strings(refs)
		assert.Equal(t, []string{"ref1", "ref2"}, refs)
	})

	t.Run("both empty", func(t *testing.T) {
		a := &[]cyclonedx.BOMReference{}
		b := &[]cyclonedx.BOMReference{}

		result := mergeBOMReferenceSlice(a, b)

		assert.Nil(t, result)
	})

	t.Run("complete duplicates", func(t *testing.T) {
		a := &[]cyclonedx.BOMReference{"ref1", "ref2"}
		b := &[]cyclonedx.BOMReference{"ref1", "ref2"}

		result := mergeBOMReferenceSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Sort for predictable testing
		refs := make([]string, len(*result))
		for i, ref := range *result {
			refs[i] = string(ref)
		}
		sort.Strings(refs)
		assert.Equal(t, []string{"ref1", "ref2"}, refs)
	})
}

func TestMergeCompositionSlice_Immutability(t *testing.T) {
	t.Run("original slices are not modified", func(t *testing.T) {
		originalA := &[]cyclonedx.Composition{
			{
				BOMRef:    "comp-a",
				Aggregate: cyclonedx.CompositionAggregateComplete,
				Assemblies: &[]cyclonedx.BOMReference{
					"assembly1", "assembly2",
				},
			},
		}
		originalB := &[]cyclonedx.Composition{
			{
				BOMRef:    "comp-a", // Same BOMRef for merging
				Aggregate: cyclonedx.CompositionAggregateIncomplete,
				Dependencies: &[]cyclonedx.BOMReference{
					"dep1", "dep2",
				},
			},
		}

		// Create copies for comparison
		copyA := &[]cyclonedx.Composition{
			{
				BOMRef:    (*originalA)[0].BOMRef,
				Aggregate: (*originalA)[0].Aggregate,
				Assemblies: &[]cyclonedx.BOMReference{
					(*(*originalA)[0].Assemblies)[0], (*(*originalA)[0].Assemblies)[1],
				},
			},
		}
		copyB := &[]cyclonedx.Composition{
			{
				BOMRef:    (*originalB)[0].BOMRef,
				Aggregate: (*originalB)[0].Aggregate,
				Dependencies: &[]cyclonedx.BOMReference{
					(*(*originalB)[0].Dependencies)[0], (*(*originalB)[0].Dependencies)[1],
				},
			},
		}

		result := mergeCompositionSlice(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, (*copyA)[0].BOMRef, (*originalA)[0].BOMRef)
		assert.Equal(t, (*copyA)[0].Aggregate, (*originalA)[0].Aggregate)
		assert.Equal(t, *(*copyA)[0].Assemblies, *(*originalA)[0].Assemblies)

		assert.Equal(t, (*copyB)[0].BOMRef, (*originalB)[0].BOMRef)
		assert.Equal(t, (*copyB)[0].Aggregate, (*originalB)[0].Aggregate)
		assert.Equal(t, *(*copyB)[0].Dependencies, *(*originalB)[0].Dependencies)

		// Verify result is merged correctly
		assert.NotNil(t, result)
		assert.Len(t, *result, 1) // One merged composition
		assert.Equal(t, "comp-a", (*result)[0].BOMRef)
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, (*result)[0].Aggregate) // First input wins

		// Both arrays should be present in result
		assert.NotNil(t, (*result)[0].Assemblies)
		assert.Len(t, *(*result)[0].Assemblies, 2)
		assert.NotNil(t, (*result)[0].Dependencies)
		assert.Len(t, *(*result)[0].Dependencies, 2)
	})
}