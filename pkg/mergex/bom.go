package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// MergeBom merges two cyclonedx.BOM structs non-destructively.
// For non-array fields, the first input (a) takes precedence.
// For array fields, items from both inputs are combined.
// Returns a new BOM struct without modifying the inputs.
func MergeBom(a, b *cyclonedx.BOM) *cyclonedx.BOM {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		return copyBOM(b)
	}

	if b == nil {
		// Deep copy a
		return copyBOM(a)
	}

	// Start with deep copy of a as base
	result := copyBOM(a)

	// Fill empty simple fields from b where a is empty
	if result.SerialNumber == "" {
		result.SerialNumber = b.SerialNumber
	}

	// Version is int, use first input if non-zero, otherwise use second
	if result.Version == 0 {
		result.Version = b.Version
	}

	// Fill empty format/schema fields from b where a is empty
	if result.JSONSchema == "" {
		result.JSONSchema = b.JSONSchema
	}
	if result.BOMFormat == "" {
		result.BOMFormat = b.BOMFormat
	}
	if result.XMLNS == "" {
		result.XMLNS = b.XMLNS
	}

	// SpecVersion - use first input if set, otherwise use second
	if result.SpecVersion == 0 {
		result.SpecVersion = b.SpecVersion
	}

	// Merge complex fields we have implemented
	if result.Metadata == nil {
		result.Metadata = copyMetadata(b.Metadata)
	} else if b.Metadata != nil {
		result.Metadata = mergeMetadata(result.Metadata, b.Metadata)
	}

	// Merge array fields with proper merge functions
	result.Components = mergeComponentSlice(result.Components, b.Components)

	// Special handling for root component dependencies - this also handles regular merge
	// but excludes the second BOM's root dependencies to avoid duplication
	result.Dependencies = mergeRootComponentDependencies(result, b)
	result.Properties = mergePropertySlice(result.Properties, b.Properties)
	result.ExternalReferences = mergeExternalReferenceSlice(result.ExternalReferences, b.ExternalReferences)
	result.Services = mergeServiceSliceInternal(result.Services, b.Services)
	result.Compositions = mergeCompositionSlice(result.Compositions, b.Compositions)
	result.Vulnerabilities = mergeVulnerabilitySlice(result.Vulnerabilities, b.Vulnerabilities)
	result.Annotations = mergeAnnotationSlice(result.Annotations, b.Annotations)
	result.Formulation = mergeFormulaSlice(result.Formulation, b.Formulation)

	// Merge complex singleton fields
	if result.Declarations == nil {
		result.Declarations = mergeDeclarations(nil, b.Declarations)
	} else {
		result.Declarations = mergeDeclarations(result.Declarations, b.Declarations)
	}

	if result.Definitions == nil {
		result.Definitions = mergeDefinitions(nil, b.Definitions)
	} else {
		result.Definitions = mergeDefinitions(result.Definitions, b.Definitions)
	}

	return result
}

// MergeBomAsDependency merges two BOMs by adding the second BOM's root component
// as a dependency of the first BOM. The second BOM's root component (metadata.component)
// is added to the components list and dependencies list of the first BOM.
// All other components and dependencies from the second BOM are also merged.
// If both BOMs have the same root component (same BOMRef OR same name+version+purl),
// performs a regular merge instead to avoid self-dependencies.
// Returns a new BOM struct without modifying the inputs.
func MergeBomAsDependency(a, b *cyclonedx.BOM) *cyclonedx.BOM {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		return copyBOM(b)
	}

	if b == nil {
		// Deep copy a
		return copyBOM(a)
	}

	// Check if both BOMs have the same root component
	if hasSameRootComponent(a, b) {
		// If same root component, just do regular merge to avoid self-dependency
		return MergeBom(a, b)
	}

	// Start with deep copy of a as base
	result := copyBOM(a)

	// If b has a root component in metadata, add it as a dependency
	if b.Metadata != nil && b.Metadata.Component != nil {
		rootComponent := b.Metadata.Component

		// Add the root component to the components list
		if result.Components == nil {
			result.Components = &[]cyclonedx.Component{}
		}
		*result.Components = append(*result.Components, *rootComponent)

		// Add a dependency entry for the root component if it has a BOMRef
		if rootComponent.BOMRef != "" {
			newDep := cyclonedx.Dependency{
				Ref: rootComponent.BOMRef,
			}

			// If the root component of the first BOM exists and has a BOMRef,
			// add this new dependency to its dependencies list
			if result.Metadata != nil && result.Metadata.Component != nil && result.Metadata.Component.BOMRef != "" {
				// Find or create the dependency entry for the root component
				if result.Dependencies == nil {
					result.Dependencies = &[]cyclonedx.Dependency{}
				}

				// Look for existing dependency entry for the root component
				var rootDepIndex = -1
				for i, dep := range *result.Dependencies {
					if dep.Ref == result.Metadata.Component.BOMRef {
						rootDepIndex = i
						break
					}
				}

				if rootDepIndex >= 0 {
					// Add to existing root dependency
					if (*result.Dependencies)[rootDepIndex].Dependencies == nil {
						(*result.Dependencies)[rootDepIndex].Dependencies = &[]string{}
					}
					*(*result.Dependencies)[rootDepIndex].Dependencies = append(*(*result.Dependencies)[rootDepIndex].Dependencies, rootComponent.BOMRef)
				} else {
					// Create new root dependency with this component as a dependency
					rootDep := cyclonedx.Dependency{
						Ref:          result.Metadata.Component.BOMRef,
						Dependencies: &[]string{rootComponent.BOMRef},
					}
					*result.Dependencies = append(*result.Dependencies, rootDep)
				}
			}

			// Also add the new component as its own dependency entry (if it has dependencies from b)
			if result.Dependencies == nil {
				result.Dependencies = &[]cyclonedx.Dependency{}
			}
			*result.Dependencies = append(*result.Dependencies, newDep)
		}
	}

	// Merge all other components and dependencies from b
	result.Components = mergeComponentSlice(result.Components, b.Components)
	result.Dependencies = mergeDependencySlice(result.Dependencies, b.Dependencies)

	// Merge other fields from b
	result.Properties = mergePropertySlice(result.Properties, b.Properties)
	result.ExternalReferences = mergeExternalReferenceSlice(result.ExternalReferences, b.ExternalReferences)
	result.Services = mergeServiceSliceInternal(result.Services, b.Services)
	result.Compositions = mergeCompositionSlice(result.Compositions, b.Compositions)
	result.Vulnerabilities = mergeVulnerabilitySlice(result.Vulnerabilities, b.Vulnerabilities)
	result.Annotations = mergeAnnotationSlice(result.Annotations, b.Annotations)
	result.Formulation = mergeFormulaSlice(result.Formulation, b.Formulation)

	// Merge complex singleton fields
	if result.Declarations == nil {
		result.Declarations = mergeDeclarations(nil, b.Declarations)
	} else {
		result.Declarations = mergeDeclarations(result.Declarations, b.Declarations)
	}

	if result.Definitions == nil {
		result.Definitions = mergeDefinitions(nil, b.Definitions)
	} else {
		result.Definitions = mergeDefinitions(result.Definitions, b.Definitions)
	}

	return result
}

func MergeBomsAsDependency(boms []*cyclonedx.BOM) *cyclonedx.BOM {
	if len(boms) == 0 {
		return nil
	}

	if len(boms) == 1 {
		return copyBOM(boms[0])
	}

	merged := boms[0]
	for i := 1; i < len(boms); i++ {
		merged = MergeBomAsDependency(merged, boms[i])
	}
	return merged
}

func MergeBoms(boms []*cyclonedx.BOM) *cyclonedx.BOM {
	if len(boms) == 0 {
		return nil
	}

	if len(boms) == 1 {
		return copyBOM(boms[0])
	}

	merged := boms[0]
	for i := 1; i < len(boms); i++ {
		merged = MergeBom(merged, boms[i])
	}
	return merged
}

// hasSameRootComponent checks if two BOMs have the same root component.
// Components are considered the same if they have:
// 1. The same non-empty BOMRef, OR
// 2. The same combination of name+version+packageURL (all non-empty)
func hasSameRootComponent(a, b *cyclonedx.BOM) bool {
	// Check for nil BOMs first
	if a == nil || b == nil {
		return false
	}

	// Extract root components
	var compA, compB *cyclonedx.Component
	if a.Metadata != nil {
		compA = a.Metadata.Component
	}
	if b.Metadata != nil {
		compB = b.Metadata.Component
	}

	// If either BOM has no root component, they're not the same
	if compA == nil || compB == nil {
		return false
	}

	// Check BOMRef equality (if both have non-empty BOMRef)
	if compA.BOMRef != "" && compB.BOMRef != "" {
		return compA.BOMRef == compB.BOMRef
	}

	// Check name+version+packageURL equality (all must be non-empty and equal)
	if compA.Name != "" && compB.Name != "" &&
		compA.Version != "" && compB.Version != "" &&
		compA.PackageURL != "" && compB.PackageURL != "" {
		return compA.Name == compB.Name &&
			compA.Version == compB.Version &&
			compA.PackageURL == compB.PackageURL
	}

	// If we can't determine they're the same, assume they're different
	return false
}

// mergeRootComponentDependencies handles the special case where the second BOM's root component
// has dependencies that need to be transferred to the first BOM's root component.
// It also performs the complete dependency merge, excluding the second BOM's root dependencies
// to avoid duplication. This only applies to regular MergeBom, not MergeBomAsDependency.
func mergeRootComponentDependencies(result, b *cyclonedx.BOM) *[]cyclonedx.Dependency {
	// Get the root component BOMRefs
	var resultRootRef, bRootRef string
	if result.Metadata != nil && result.Metadata.Component != nil {
		resultRootRef = result.Metadata.Component.BOMRef
	}
	if b.Metadata != nil && b.Metadata.Component != nil {
		bRootRef = b.Metadata.Component.BOMRef
	}

	// If either root component has no BOMRef, or they are the same, use regular merge
	if resultRootRef == "" || bRootRef == "" || resultRootRef == bRootRef {
		return mergeDependencySlice(result.Dependencies, b.Dependencies)
	}

	// Special case: different root components
	// First, transfer the second BOM's root dependencies to the first BOM's root
	if b.Dependencies != nil {
		var bRootDependencies *[]string
		for _, dep := range *b.Dependencies {
			if dep.Ref == bRootRef {
				bRootDependencies = dep.Dependencies
				break
			}
		}

		// If the second BOM's root has dependencies, transfer them
		if bRootDependencies != nil && len(*bRootDependencies) > 0 {
			// Ensure result.Dependencies is initialized
			if result.Dependencies == nil {
				result.Dependencies = &[]cyclonedx.Dependency{}
			}

			// Find or create the dependency entry for the result's root component
			var resultRootDepIndex = -1
			for i, dep := range *result.Dependencies {
				if dep.Ref == resultRootRef {
					resultRootDepIndex = i
					break
				}
			}

			if resultRootDepIndex >= 0 {
				// Add b's root dependencies to existing result root dependency
				if (*result.Dependencies)[resultRootDepIndex].Dependencies == nil {
					(*result.Dependencies)[resultRootDepIndex].Dependencies = &[]string{}
				}

				// Use the string deduplication helper to merge dependencies
				(*result.Dependencies)[resultRootDepIndex].Dependencies = mergeStringSliceWithDeduplication(
					(*result.Dependencies)[resultRootDepIndex].Dependencies,
					bRootDependencies,
				)
			} else {
				// Create new root dependency with b's dependencies
				newRootDep := cyclonedx.Dependency{
					Ref:          resultRootRef,
					Dependencies: &[]string{},
				}

				// Copy b's root dependencies
				*newRootDep.Dependencies = append(*newRootDep.Dependencies, *bRootDependencies...)
				*result.Dependencies = append(*result.Dependencies, newRootDep)
			}
		}
	}

	// Now merge all other dependencies from b, but exclude b's root component
	if b.Dependencies != nil {
		// Create a filtered version of b.Dependencies without the root component
		filteredBDeps := make([]cyclonedx.Dependency, 0)
		for _, dep := range *b.Dependencies {
			if dep.Ref != bRootRef {
				filteredBDeps = append(filteredBDeps, dep)
			}
		}

		// Merge with the filtered dependencies
		if len(filteredBDeps) > 0 {
			result.Dependencies = mergeDependencySlice(result.Dependencies, &filteredBDeps)
		}
	}

	return result.Dependencies
}

// copyBOM creates a deep copy of a BOM struct
func copyBOM(bom *cyclonedx.BOM) *cyclonedx.BOM {
	if bom == nil {
		return nil
	}

	result := &cyclonedx.BOM{
		XMLName:      bom.XMLName,
		XMLNS:        bom.XMLNS,
		JSONSchema:   bom.JSONSchema,
		BOMFormat:    bom.BOMFormat,
		SpecVersion:  bom.SpecVersion,
		SerialNumber: bom.SerialNumber,
		Version:      bom.Version,
	}

	result.Metadata = copyMetadata(bom.Metadata)
	result.Components = copyComponentSlice(bom.Components)
	result.ExternalReferences = copyExternalReferenceSlice(bom.ExternalReferences)
	result.Dependencies = copyDependencySlice(bom.Dependencies)
	result.Properties = copyPropertySlice(bom.Properties)
	result.Services = copyServiceSlice(bom.Services)
	result.Compositions = copyCompositionSlice(bom.Compositions)
	result.Vulnerabilities = copyVulnerabilitySlice(bom.Vulnerabilities)
	result.Annotations = copyAnnotationSlice(bom.Annotations)
	result.Formulation = copyFormulaSlice(bom.Formulation)
	result.Declarations = copyDeclarations(bom.Declarations)
	result.Definitions = copyDefinitions(bom.Definitions)

	return result
}

// Helper copy functions for implemented types
func copyExternalReferenceSlice(er *[]cyclonedx.ExternalReference) *[]cyclonedx.ExternalReference {
	if er == nil {
		return nil
	}
	result := make([]cyclonedx.ExternalReference, len(*er))
	copy(result, *er)
	return &result
}

func copyDependencySlice(d *[]cyclonedx.Dependency) *[]cyclonedx.Dependency {
	if d == nil {
		return nil
	}
	result := make([]cyclonedx.Dependency, len(*d))
	copy(result, *d)
	return &result
}
