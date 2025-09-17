package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeDependency merges two cyclonedx.Dependency structs non-destructively.
// Since Ref is a unique identifier, this function assumes both dependencies have the same Ref.
// The Dependencies arrays are combined and deduplicated.
// Returns a new Dependency struct without modifying the inputs.
func mergeDependency(a, b cyclonedx.Dependency) cyclonedx.Dependency {
	result := cyclonedx.Dependency{
		Ref: a.Ref, // Both should have the same Ref, use first input
	}

	// Merge Dependencies arrays with deduplication
	result.Dependencies = mergeStringSliceWithDeduplication(a.Dependencies, b.Dependencies)

	return result
}

// mergeDependencySlice merges two Dependency slices non-destructively.
// Dependencies with the same Ref are merged together.
// Dependencies with unique Refs are included as-is.
// Returns a new slice without modifying the inputs.
func mergeDependencySlice(a, b *[]cyclonedx.Dependency) *[]cyclonedx.Dependency {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track dependencies by Ref
	depMap := make(map[string]cyclonedx.Dependency)

	// First add all dependencies from a
	if a != nil {
		for _, dep := range *a {
			depMap[dep.Ref] = dep
		}
	}

	// Then process dependencies from b
	if b != nil {
		for _, dep := range *b {
			if existing, exists := depMap[dep.Ref]; exists {
				// Merge with existing dependency (same Ref)
				depMap[dep.Ref] = mergeDependency(existing, dep)
			} else {
				// Add new dependency (unique Ref)
				depMap[dep.Ref] = dep
			}
		}
	}

	if len(depMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Dependency, 0, len(depMap))
	for _, dep := range depMap {
		result = append(result, dep)
	}

	return &result
}

// mergeStringSliceWithDeduplication merges two string slices and removes duplicates
func mergeStringSliceWithDeduplication(a, b *[]string) *[]string {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track unique strings
	strMap := make(map[string]bool)

	// Add strings from both slices
	if a != nil {
		for _, s := range *a {
			strMap[s] = true
		}
	}
	if b != nil {
		for _, s := range *b {
			strMap[s] = true
		}
	}

	if len(strMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]string, 0, len(strMap))
	for s := range strMap {
		result = append(result, s)
	}

	return &result
}