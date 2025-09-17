package mergex

import (
	"sort"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeDependency(t *testing.T) {
	t.Run("merge dependencies with same ref", func(t *testing.T) {
		a := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: &[]string{"dep1", "dep2"},
		}
		b := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: &[]string{"dep2", "dep3"},
		}

		result := mergeDependency(a, b)

		assert.Equal(t, "component-a", result.Ref)
		assert.NotNil(t, result.Dependencies)
		
		// Convert to slice and sort for predictable testing
		deps := *result.Dependencies
		sort.Strings(deps)
		assert.Len(t, deps, 3)
		assert.Equal(t, []string{"dep1", "dep2", "dep3"}, deps)
	})

	t.Run("merge dependencies with nil arrays", func(t *testing.T) {
		a := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: &[]string{"dep1"},
		}
		b := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: nil,
		}

		result := mergeDependency(a, b)

		assert.Equal(t, "component-a", result.Ref)
		assert.NotNil(t, result.Dependencies)
		assert.Equal(t, []string{"dep1"}, *result.Dependencies)
	})

	t.Run("merge dependencies with both nil arrays", func(t *testing.T) {
		a := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: nil,
		}
		b := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: nil,
		}

		result := mergeDependency(a, b)

		assert.Equal(t, "component-a", result.Ref)
		assert.Nil(t, result.Dependencies)
	})

	t.Run("merge dependencies with empty arrays", func(t *testing.T) {
		a := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: &[]string{},
		}
		b := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: &[]string{},
		}

		result := mergeDependency(a, b)

		assert.Equal(t, "component-a", result.Ref)
		assert.Nil(t, result.Dependencies) // Empty slices result in nil
	})

	t.Run("merge dependencies with duplicates only", func(t *testing.T) {
		a := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: &[]string{"dep1", "dep2"},
		}
		b := cyclonedx.Dependency{
			Ref:          "component-a",
			Dependencies: &[]string{"dep1", "dep2"},
		}

		result := mergeDependency(a, b)

		assert.Equal(t, "component-a", result.Ref)
		assert.NotNil(t, result.Dependencies)
		
		// Convert to slice and sort for predictable testing
		deps := *result.Dependencies
		sort.Strings(deps)
		assert.Len(t, deps, 2)
		assert.Equal(t, []string{"dep1", "dep2"}, deps)
	})
}

func TestMergeDependencySlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeDependencySlice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.Dependency{
			{
				Ref:          "component-b",
				Dependencies: &[]string{"dep1"},
			},
		}

		result := mergeDependencySlice(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "component-b", (*result)[0].Ref)
		assert.Equal(t, []string{"dep1"}, *(*result)[0].Dependencies)
	})

	t.Run("merge slices with no overlapping refs", func(t *testing.T) {
		a := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a",
				Dependencies: &[]string{"dep1", "dep2"},
			},
		}
		b := &[]cyclonedx.Dependency{
			{
				Ref:          "component-b",
				Dependencies: &[]string{"dep3", "dep4"},
			},
		}

		result := mergeDependencySlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Convert to map for easier testing since order is not guaranteed
		depMap := make(map[string][]string)
		for _, dep := range *result {
			if dep.Dependencies != nil {
				deps := *dep.Dependencies
				sort.Strings(deps)
				depMap[dep.Ref] = deps
			}
		}

		assert.Equal(t, []string{"dep1", "dep2"}, depMap["component-a"])
		assert.Equal(t, []string{"dep3", "dep4"}, depMap["component-b"])
	})

	t.Run("merge slices with overlapping refs", func(t *testing.T) {
		a := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a",
				Dependencies: &[]string{"dep1", "dep2"},
			},
			{
				Ref:          "component-b",
				Dependencies: &[]string{"dep3"},
			},
		}
		b := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a", // Same ref as in a
				Dependencies: &[]string{"dep2", "dep4"}, // dep2 is duplicate
			},
			{
				Ref:          "component-c",
				Dependencies: &[]string{"dep5"},
			},
		}

		result := mergeDependencySlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // component-a merged, component-b and component-c separate

		// Convert to map for easier testing since order is not guaranteed
		depMap := make(map[string][]string)
		for _, dep := range *result {
			if dep.Dependencies != nil {
				deps := *dep.Dependencies
				sort.Strings(deps)
				depMap[dep.Ref] = deps
			}
		}

		// component-a should have merged and deduplicated dependencies
		assert.Equal(t, []string{"dep1", "dep2", "dep4"}, depMap["component-a"])
		assert.Equal(t, []string{"dep3"}, depMap["component-b"])
		assert.Equal(t, []string{"dep5"}, depMap["component-c"])
	})

	t.Run("merge slices with complete ref overlap", func(t *testing.T) {
		a := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a",
				Dependencies: &[]string{"dep1", "dep2"},
			},
			{
				Ref:          "component-b",
				Dependencies: &[]string{"dep3"},
			},
		}
		b := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a", // Same as first in a
				Dependencies: &[]string{"dep4", "dep5"},
			},
			{
				Ref:          "component-b", // Same as second in a
				Dependencies: &[]string{"dep6"},
			},
		}

		result := mergeDependencySlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2) // Both refs merged

		// Convert to map for easier testing since order is not guaranteed
		depMap := make(map[string][]string)
		for _, dep := range *result {
			if dep.Dependencies != nil {
				deps := *dep.Dependencies
				sort.Strings(deps)
				depMap[dep.Ref] = deps
			}
		}

		assert.Equal(t, []string{"dep1", "dep2", "dep4", "dep5"}, depMap["component-a"])
		assert.Equal(t, []string{"dep3", "dep6"}, depMap["component-b"])
	})

	t.Run("merge slices with nil dependencies", func(t *testing.T) {
		a := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a",
				Dependencies: &[]string{"dep1"},
			},
		}
		b := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a", // Same ref
				Dependencies: nil,         // Nil dependencies
			},
		}

		result := mergeDependencySlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "component-a", (*result)[0].Ref)
		assert.NotNil(t, (*result)[0].Dependencies)
		assert.Equal(t, []string{"dep1"}, *(*result)[0].Dependencies)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.Dependency{}
		b := &[]cyclonedx.Dependency{}

		result := mergeDependencySlice(a, b)

		assert.Nil(t, result)
	})
}

func TestMergeStringSliceWithDeduplication(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeStringSliceWithDeduplication(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("no duplicates", func(t *testing.T) {
		a := &[]string{"dep1", "dep2"}
		b := &[]string{"dep3", "dep4"}

		result := mergeStringSliceWithDeduplication(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 4)
		
		// Sort for predictable testing
		deps := *result
		sort.Strings(deps)
		assert.Equal(t, []string{"dep1", "dep2", "dep3", "dep4"}, deps)
	})

	t.Run("with duplicates", func(t *testing.T) {
		a := &[]string{"dep1", "dep2", "dep3"}
		b := &[]string{"dep2", "dep3", "dep4"}

		result := mergeStringSliceWithDeduplication(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 4) // dep2 and dep3 are deduplicated
		
		// Sort for predictable testing
		deps := *result
		sort.Strings(deps)
		assert.Equal(t, []string{"dep1", "dep2", "dep3", "dep4"}, deps)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]string{"dep1", "dep2"}

		result := mergeStringSliceWithDeduplication(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)
		
		// Sort for predictable testing
		deps := *result
		sort.Strings(deps)
		assert.Equal(t, []string{"dep1", "dep2"}, deps)
	})

	t.Run("both empty", func(t *testing.T) {
		a := &[]string{}
		b := &[]string{}

		result := mergeStringSliceWithDeduplication(a, b)

		assert.Nil(t, result)
	})

	t.Run("complete duplicates", func(t *testing.T) {
		a := &[]string{"dep1", "dep2"}
		b := &[]string{"dep1", "dep2"}

		result := mergeStringSliceWithDeduplication(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)
		
		// Sort for predictable testing
		deps := *result
		sort.Strings(deps)
		assert.Equal(t, []string{"dep1", "dep2"}, deps)
	})
}

func TestMergeDependencySlice_Immutability(t *testing.T) {
	t.Run("original slices are not modified", func(t *testing.T) {
		originalA := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a",
				Dependencies: &[]string{"dep1", "dep2"},
			},
		}
		originalB := &[]cyclonedx.Dependency{
			{
				Ref:          "component-a", // Same ref for merging
				Dependencies: &[]string{"dep3", "dep4"},
			},
		}

		// Create copies for comparison
		copyA := &[]cyclonedx.Dependency{
			{
				Ref:          (*originalA)[0].Ref,
				Dependencies: &[]string{(*(*originalA)[0].Dependencies)[0], (*(*originalA)[0].Dependencies)[1]},
			},
		}
		copyB := &[]cyclonedx.Dependency{
			{
				Ref:          (*originalB)[0].Ref,
				Dependencies: &[]string{(*(*originalB)[0].Dependencies)[0], (*(*originalB)[0].Dependencies)[1]},
			},
		}

		result := mergeDependencySlice(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, (*copyA)[0].Ref, (*originalA)[0].Ref)
		assert.Equal(t, *(*copyA)[0].Dependencies, *(*originalA)[0].Dependencies)
		
		assert.Equal(t, (*copyB)[0].Ref, (*originalB)[0].Ref)
		assert.Equal(t, *(*copyB)[0].Dependencies, *(*originalB)[0].Dependencies)

		// Verify result is merged correctly
		assert.NotNil(t, result)
		assert.Len(t, *result, 1) // One merged dependency
		assert.Equal(t, "component-a", (*result)[0].Ref)
		assert.NotNil(t, (*result)[0].Dependencies)
		
		// Sort for predictable testing
		deps := *(*result)[0].Dependencies
		sort.Strings(deps)
		assert.Equal(t, []string{"dep1", "dep2", "dep3", "dep4"}, deps)
	})
}