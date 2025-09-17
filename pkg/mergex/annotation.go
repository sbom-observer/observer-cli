package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeAnnotation merges two cyclonedx.Annotation structs non-destructively.
// Since BOMRef is a unique identifier, this function assumes both annotations have the same BOMRef.
// For non-array fields, the first input takes precedence.
// For array fields, items from both inputs are combined and deduplicated.
// Returns a new Annotation struct without modifying the inputs.
func mergeAnnotation(a, b cyclonedx.Annotation) cyclonedx.Annotation {
	result := cyclonedx.Annotation{
		BOMRef: a.BOMRef, // Both should have the same BOMRef, use first input
	}

	// Fill empty simple fields from b where a is empty
	if a.Timestamp == "" {
		result.Timestamp = b.Timestamp
	} else {
		result.Timestamp = a.Timestamp
	}
	if a.Text == "" {
		result.Text = b.Text
	} else {
		result.Text = a.Text
	}

	// Merge complex fields
	if a.Annotator == nil {
		result.Annotator = copyAnnotator(b.Annotator)
	} else if b.Annotator != nil {
		result.Annotator = mergeAnnotator(a.Annotator, b.Annotator)
	} else {
		result.Annotator = copyAnnotator(a.Annotator)
	}

	// Merge array fields with deduplication
	result.Subjects = mergeBOMReferenceSlice(a.Subjects, b.Subjects)

	return result
}

// mergeAnnotationSlice merges two Annotation slices non-destructively.
// Annotations with the same BOMRef are merged together.
// Annotations with unique BOMRefs are included as-is.
// Returns a new slice without modifying the inputs.
func mergeAnnotationSlice(a, b *[]cyclonedx.Annotation) *[]cyclonedx.Annotation {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track annotations by BOMRef
	annotationMap := make(map[string]cyclonedx.Annotation)

	// First add all annotations from a
	if a != nil {
		for _, ann := range *a {
			annotationMap[ann.BOMRef] = ann
		}
	}

	// Then process annotations from b
	if b != nil {
		for _, ann := range *b {
			if existing, exists := annotationMap[ann.BOMRef]; exists {
				// Merge with existing annotation (same BOMRef)
				annotationMap[ann.BOMRef] = mergeAnnotation(existing, ann)
			} else {
				// Add new annotation (unique BOMRef)
				annotationMap[ann.BOMRef] = ann
			}
		}
	}

	if len(annotationMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Annotation, 0, len(annotationMap))
	for _, ann := range annotationMap {
		result = append(result, ann)
	}

	return &result
}

// Helper functions for Annotator

func copyAnnotator(annotator *cyclonedx.Annotator) *cyclonedx.Annotator {
	if annotator == nil {
		return nil
	}

	result := &cyclonedx.Annotator{}

	if annotator.Organization != nil {
		copy := *annotator.Organization
		result.Organization = &copy
	}

	if annotator.Individual != nil {
		copy := *annotator.Individual
		result.Individual = &copy
	}

	if annotator.Component != nil {
		copy := *annotator.Component
		result.Component = &copy
	}

	if annotator.Service != nil {
		copy := *annotator.Service
		result.Service = &copy
	}

	return result
}

func mergeAnnotator(a, b *cyclonedx.Annotator) *cyclonedx.Annotator {
	if a == nil {
		return copyAnnotator(b)
	}
	if b == nil {
		return copyAnnotator(a)
	}

	result := &cyclonedx.Annotator{}

	// First input wins for each annotator type
	if a.Organization != nil {
		copy := *a.Organization
		result.Organization = &copy
	} else if b.Organization != nil {
		copy := *b.Organization
		result.Organization = &copy
	}

	if a.Individual != nil {
		copy := *a.Individual
		result.Individual = &copy
	} else if b.Individual != nil {
		copy := *b.Individual
		result.Individual = &copy
	}

	if a.Component != nil {
		copy := *a.Component
		result.Component = &copy
	} else if b.Component != nil {
		copy := *b.Component
		result.Component = &copy
	}

	if a.Service != nil {
		copy := *a.Service
		result.Service = &copy
	} else if b.Service != nil {
		copy := *b.Service
		result.Service = &copy
	}

	return result
}

func copyAnnotationSlice(annotations *[]cyclonedx.Annotation) *[]cyclonedx.Annotation {
	if annotations == nil {
		return nil
	}
	result := make([]cyclonedx.Annotation, len(*annotations))
	copy(result, *annotations)
	return &result
}