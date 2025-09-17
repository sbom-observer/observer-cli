package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeComposition merges two cyclonedx.Composition structs non-destructively.
// Since BOMRef is a unique identifier, this function assumes both compositions have the same BOMRef.
// The Aggregate field uses first input precedence.
// The array fields (Assemblies, Dependencies, Vulnerabilities) are combined and deduplicated.
// Returns a new Composition struct without modifying the inputs.
func mergeComposition(a, b cyclonedx.Composition) cyclonedx.Composition {
	result := cyclonedx.Composition{
		BOMRef:    a.BOMRef, // Both should have the same BOMRef, use first input
		Aggregate: a.Aggregate, // First input wins
	}

	// Merge array fields with deduplication
	result.Assemblies = mergeBOMReferenceSlice(a.Assemblies, b.Assemblies)
	result.Dependencies = mergeBOMReferenceSlice(a.Dependencies, b.Dependencies)
	result.Vulnerabilities = mergeBOMReferenceSlice(a.Vulnerabilities, b.Vulnerabilities)

	return result
}

// mergeCompositionSlice merges two Composition slices non-destructively.
// Compositions with the same BOMRef are merged together.
// Compositions with unique BOMRefs are included as-is.
// Returns a new slice without modifying the inputs.
func mergeCompositionSlice(a, b *[]cyclonedx.Composition) *[]cyclonedx.Composition {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track compositions by BOMRef
	compMap := make(map[string]cyclonedx.Composition)

	// First add all compositions from a
	if a != nil {
		for _, comp := range *a {
			compMap[comp.BOMRef] = comp
		}
	}

	// Then process compositions from b
	if b != nil {
		for _, comp := range *b {
			if existing, exists := compMap[comp.BOMRef]; exists {
				// Merge with existing composition (same BOMRef)
				compMap[comp.BOMRef] = mergeComposition(existing, comp)
			} else {
				// Add new composition (unique BOMRef)
				compMap[comp.BOMRef] = comp
			}
		}
	}

	if len(compMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Composition, 0, len(compMap))
	for _, comp := range compMap {
		result = append(result, comp)
	}

	return &result
}

// mergeBOMReferenceSlice merges two BOMReference slices and removes duplicates
func mergeBOMReferenceSlice(a, b *[]cyclonedx.BOMReference) *[]cyclonedx.BOMReference {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track unique BOM references
	refMap := make(map[cyclonedx.BOMReference]bool)

	// Add references from both slices
	if a != nil {
		for _, ref := range *a {
			refMap[ref] = true
		}
	}
	if b != nil {
		for _, ref := range *b {
			refMap[ref] = true
		}
	}

	if len(refMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.BOMReference, 0, len(refMap))
	for ref := range refMap {
		result = append(result, ref)
	}

	return &result
}

func copyCompositionSlice(compositions *[]cyclonedx.Composition) *[]cyclonedx.Composition {
	if compositions == nil {
		return nil
	}
	result := make([]cyclonedx.Composition, len(*compositions))
	copy(result, *compositions)
	return &result
}