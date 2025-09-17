package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeDefinitions merges two cyclonedx.Definitions structs non-destructively.
// Since Definitions is essentially a wrapper around a Standards array, this function
// merges the Standards arrays using BOMRef-based deduplication.
// Returns a new Definitions struct without modifying the inputs.
func mergeDefinitions(a, b *cyclonedx.Definitions) *cyclonedx.Definitions {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		return copyDefinitions(b)
	}
	if b == nil {
		return copyDefinitions(a)
	}

	result := &cyclonedx.Definitions{}
	result.Standards = mergeStandardDefinitionSlice(a.Standards, b.Standards)

	return result
}

// mergeStandardDefinition merges two cyclonedx.StandardDefinition structs non-destructively.
// Since BOMRef is a unique identifier, this function assumes both standards have the same BOMRef.
// For non-array fields, the first input takes precedence.
// For array fields, items from both inputs are combined.
// Returns a new StandardDefinition struct without modifying the inputs.
func mergeStandardDefinition(a, b cyclonedx.StandardDefinition) cyclonedx.StandardDefinition {
	result := cyclonedx.StandardDefinition{
		BOMRef: a.BOMRef, // Both should have the same BOMRef, use first input
	}

	// Fill empty simple fields from b where a is empty
	if a.Name == "" {
		result.Name = b.Name
	} else {
		result.Name = a.Name
	}
	if a.Version == "" {
		result.Version = b.Version
	} else {
		result.Version = a.Version
	}
	if a.Description == "" {
		result.Description = b.Description
	} else {
		result.Description = a.Description
	}
	if a.Owner == "" {
		result.Owner = b.Owner
	} else {
		result.Owner = a.Owner
	}

	// Merge complex fields
	if a.Signature != nil {
		result.Signature = copyJSFSignature(a.Signature)
	} else {
		result.Signature = copyJSFSignature(b.Signature)
	}

	// Merge array fields
	result.Requirements = mergeStandardRequirementSlice(a.Requirements, b.Requirements)
	result.Levels = mergeStandardLevelSlice(a.Levels, b.Levels)
	result.ExternalReferences = mergeExternalReferenceSlice(a.ExternalReferences, b.ExternalReferences)

	return result
}

// mergeStandardDefinitionSlice merges two StandardDefinition slices non-destructively.
// StandardDefinitions with the same BOMRef are merged together.
// StandardDefinitions with unique BOMRefs are included as-is.
// Returns a new slice without modifying the inputs.
func mergeStandardDefinitionSlice(a, b *[]cyclonedx.StandardDefinition) *[]cyclonedx.StandardDefinition {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track standards by BOMRef
	standardMap := make(map[string]cyclonedx.StandardDefinition)

	// First add all standards from a
	if a != nil {
		for _, std := range *a {
			standardMap[std.BOMRef] = std
		}
	}

	// Then process standards from b
	if b != nil {
		for _, std := range *b {
			if existing, exists := standardMap[std.BOMRef]; exists {
				// Merge with existing standard (same BOMRef)
				standardMap[std.BOMRef] = mergeStandardDefinition(existing, std)
			} else {
				// Add new standard (unique BOMRef)
				standardMap[std.BOMRef] = std
			}
		}
	}

	if len(standardMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.StandardDefinition, 0, len(standardMap))
	for _, std := range standardMap {
		result = append(result, std)
	}

	return &result
}

// Helper copy and merge functions

func copyDefinitions(definitions *cyclonedx.Definitions) *cyclonedx.Definitions {
	if definitions == nil {
		return nil
	}

	result := &cyclonedx.Definitions{}
	result.Standards = copyStandardDefinitionSlice(definitions.Standards)

	return result
}

func copyStandardDefinitionSlice(standards *[]cyclonedx.StandardDefinition) *[]cyclonedx.StandardDefinition {
	if standards == nil {
		return nil
	}
	result := make([]cyclonedx.StandardDefinition, len(*standards))
	copy(result, *standards)
	return &result
}

// Helper merge functions for array types

func mergeStandardRequirementSlice(a, b *[]cyclonedx.StandardRequirement) *[]cyclonedx.StandardRequirement {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.StandardRequirement

	if a != nil {
		result = append(result, *a...)
	}
	if b != nil {
		result = append(result, *b...)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

func mergeStandardLevelSlice(a, b *[]cyclonedx.StandardLevel) *[]cyclonedx.StandardLevel {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.StandardLevel

	if a != nil {
		result = append(result, *a...)
	}
	if b != nil {
		result = append(result, *b...)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}