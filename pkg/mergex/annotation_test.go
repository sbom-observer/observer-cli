package mergex

import (
	"sort"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeAnnotation(t *testing.T) {
	t.Run("merge annotations with same BOMRef", func(t *testing.T) {
		a := cyclonedx.Annotation{
			BOMRef:    "annotation-a",
			Timestamp: "2023-01-01T00:00:00Z",
			Text:      "First annotation text",
			Subjects:  &[]cyclonedx.BOMReference{"component-1", "component-2"},
			Annotator: &cyclonedx.Annotator{
				Organization: &cyclonedx.OrganizationalEntity{
					Name: "Organization A",
				},
			},
		}
		b := cyclonedx.Annotation{
			BOMRef:    "annotation-a",
			Timestamp: "2023-02-01T00:00:00Z", // Should not override first
			Text:      "Second annotation text", // Should not override first
			Subjects:  &[]cyclonedx.BOMReference{"component-2", "component-3"}, // component-2 is duplicate
			Annotator: &cyclonedx.Annotator{
				Individual: &cyclonedx.OrganizationalContact{
					Name: "John Doe",
				},
			},
		}

		result := mergeAnnotation(a, b)

		assert.Equal(t, "annotation-a", result.BOMRef)
		assert.Equal(t, "2023-01-01T00:00:00Z", result.Timestamp) // First input wins
		assert.Equal(t, "First annotation text", result.Text) // First input wins

		// Check subjects are merged and deduplicated
		assert.NotNil(t, result.Subjects)
		subjects := make([]string, len(*result.Subjects))
		for i, ref := range *result.Subjects {
			subjects[i] = string(ref)
		}
		sort.Strings(subjects)
		assert.Len(t, subjects, 3)
		assert.Equal(t, []string{"component-1", "component-2", "component-3"}, subjects)

		// Check annotator is merged - first input fields win
		assert.NotNil(t, result.Annotator)
		assert.NotNil(t, result.Annotator.Organization)
		assert.Equal(t, "Organization A", result.Annotator.Organization.Name)
		assert.NotNil(t, result.Annotator.Individual)
		assert.Equal(t, "John Doe", result.Annotator.Individual.Name)
	})

	t.Run("merge annotations with nil fields", func(t *testing.T) {
		a := cyclonedx.Annotation{
			BOMRef:    "annotation-a",
			Timestamp: "2023-01-01T00:00:00Z",
			Text:      "First annotation",
			Subjects:  &[]cyclonedx.BOMReference{"component-1"},
			Annotator: nil,
		}
		b := cyclonedx.Annotation{
			BOMRef:    "annotation-a",
			Timestamp: "2023-02-01T00:00:00Z",
			Text:      "Second annotation",
			Subjects:  nil,
			Annotator: &cyclonedx.Annotator{
				Organization: &cyclonedx.OrganizationalEntity{
					Name: "Organization B",
				},
			},
		}

		result := mergeAnnotation(a, b)

		assert.Equal(t, "annotation-a", result.BOMRef)
		assert.Equal(t, "2023-01-01T00:00:00Z", result.Timestamp) // First input wins
		assert.Equal(t, "First annotation", result.Text) // First input wins

		// Subjects from first should be preserved
		assert.NotNil(t, result.Subjects)
		assert.Equal(t, []cyclonedx.BOMReference{"component-1"}, *result.Subjects)

		// Annotator from second should be included
		assert.NotNil(t, result.Annotator)
		assert.NotNil(t, result.Annotator.Organization)
		assert.Equal(t, "Organization B", result.Annotator.Organization.Name)
	})

	t.Run("merge annotations with empty fields", func(t *testing.T) {
		a := cyclonedx.Annotation{
			BOMRef: "annotation-a",
			// Timestamp empty - should be filled from b
			// Text empty - should be filled from b
			Subjects: &[]cyclonedx.BOMReference{},
		}
		b := cyclonedx.Annotation{
			BOMRef:    "annotation-a",
			Timestamp: "2023-02-01T00:00:00Z", // Should fill empty field
			Text:      "Filled from second", // Should fill empty field
			Subjects:  &[]cyclonedx.BOMReference{},
		}

		result := mergeAnnotation(a, b)

		assert.Equal(t, "annotation-a", result.BOMRef)
		assert.Equal(t, "2023-02-01T00:00:00Z", result.Timestamp) // Filled from second
		assert.Equal(t, "Filled from second", result.Text) // Filled from second
		assert.Nil(t, result.Subjects) // Empty arrays result in nil
	})
}

func TestMergeAnnotationSlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeAnnotationSlice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.Annotation{
			{
				BOMRef:    "annotation-b",
				Timestamp: "2023-01-01T00:00:00Z",
				Text:      "Annotation B",
				Subjects:  &[]cyclonedx.BOMReference{"component-1"},
			},
		}

		result := mergeAnnotationSlice(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "annotation-b", (*result)[0].BOMRef)
		assert.Equal(t, "2023-01-01T00:00:00Z", (*result)[0].Timestamp)
		assert.Equal(t, "Annotation B", (*result)[0].Text)
		assert.Equal(t, []cyclonedx.BOMReference{"component-1"}, *(*result)[0].Subjects)
	})

	t.Run("merge slices with no overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Annotation{
			{
				BOMRef:    "annotation-a",
				Timestamp: "2023-01-01T00:00:00Z",
				Text:      "Annotation A",
				Subjects:  &[]cyclonedx.BOMReference{"component-1", "component-2"},
			},
		}
		b := &[]cyclonedx.Annotation{
			{
				BOMRef:    "annotation-b",
				Timestamp: "2023-02-01T00:00:00Z",
				Text:      "Annotation B",
				Subjects:  &[]cyclonedx.BOMReference{"component-3", "component-4"},
			},
		}

		result := mergeAnnotationSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Convert to map for easier testing since order is not guaranteed
		annotationMap := make(map[string]cyclonedx.Annotation)
		for _, ann := range *result {
			annotationMap[ann.BOMRef] = ann
		}

		assert.Equal(t, "2023-01-01T00:00:00Z", annotationMap["annotation-a"].Timestamp)
		assert.Equal(t, "Annotation A", annotationMap["annotation-a"].Text)
		assert.Equal(t, []cyclonedx.BOMReference{"component-1", "component-2"}, *annotationMap["annotation-a"].Subjects)

		assert.Equal(t, "2023-02-01T00:00:00Z", annotationMap["annotation-b"].Timestamp)
		assert.Equal(t, "Annotation B", annotationMap["annotation-b"].Text)
		assert.Equal(t, []cyclonedx.BOMReference{"component-3", "component-4"}, *annotationMap["annotation-b"].Subjects)
	})

	t.Run("merge slices with overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Annotation{
			{
				BOMRef:    "annotation-a",
				Timestamp: "2023-01-01T00:00:00Z",
				Text:      "Original annotation",
				Subjects:  &[]cyclonedx.BOMReference{"component-1", "component-2"},
				Annotator: &cyclonedx.Annotator{
					Organization: &cyclonedx.OrganizationalEntity{
						Name: "Org A",
					},
				},
			},
			{
				BOMRef:    "annotation-b",
				Timestamp: "2023-02-01T00:00:00Z",
				Text:      "Annotation B",
			},
		}
		b := &[]cyclonedx.Annotation{
			{
				BOMRef:    "annotation-a", // Same BOMRef as first
				Timestamp: "2023-03-01T00:00:00Z", // Should not override
				Text:      "Updated annotation", // Should not override
				Subjects:  &[]cyclonedx.BOMReference{"component-2", "component-3"}, // component-2 is duplicate
				Annotator: &cyclonedx.Annotator{
					Individual: &cyclonedx.OrganizationalContact{
						Name: "Jane Doe",
					},
				},
			},
			{
				BOMRef:    "annotation-c",
				Timestamp: "2023-04-01T00:00:00Z",
				Text:      "Annotation C",
			},
		}

		result := mergeAnnotationSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // annotation-a merged, annotation-b and annotation-c separate

		// Convert to map for easier testing since order is not guaranteed
		annotationMap := make(map[string]cyclonedx.Annotation)
		for _, ann := range *result {
			annotationMap[ann.BOMRef] = ann
		}

		// annotation-a should have merged fields and first input precedence
		assert.Equal(t, "2023-01-01T00:00:00Z", annotationMap["annotation-a"].Timestamp) // First input wins
		assert.Equal(t, "Original annotation", annotationMap["annotation-a"].Text) // First input wins

		// Check subjects are merged and deduplicated
		subjects := make([]string, len(*annotationMap["annotation-a"].Subjects))
		for i, ref := range *annotationMap["annotation-a"].Subjects {
			subjects[i] = string(ref)
		}
		sort.Strings(subjects)
		assert.Equal(t, []string{"component-1", "component-2", "component-3"}, subjects)

		// Check annotator is merged
		assert.NotNil(t, annotationMap["annotation-a"].Annotator.Organization)
		assert.Equal(t, "Org A", annotationMap["annotation-a"].Annotator.Organization.Name)
		assert.NotNil(t, annotationMap["annotation-a"].Annotator.Individual)
		assert.Equal(t, "Jane Doe", annotationMap["annotation-a"].Annotator.Individual.Name)

		// annotation-b should remain unchanged
		assert.Equal(t, "2023-02-01T00:00:00Z", annotationMap["annotation-b"].Timestamp)
		assert.Equal(t, "Annotation B", annotationMap["annotation-b"].Text)

		// annotation-c should be added as-is
		assert.Equal(t, "2023-04-01T00:00:00Z", annotationMap["annotation-c"].Timestamp)
		assert.Equal(t, "Annotation C", annotationMap["annotation-c"].Text)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.Annotation{}
		b := &[]cyclonedx.Annotation{}

		result := mergeAnnotationSlice(a, b)

		assert.Nil(t, result)
	})
}

func TestMergeAnnotator(t *testing.T) {
	t.Run("merge annotators with different types", func(t *testing.T) {
		a := &cyclonedx.Annotator{
			Organization: &cyclonedx.OrganizationalEntity{
				Name: "Organization A",
			},
			Component: &cyclonedx.Component{
				Name: "Component A",
			},
		}
		b := &cyclonedx.Annotator{
			Individual: &cyclonedx.OrganizationalContact{
				Name: "John Doe",
			},
			Service: &cyclonedx.Service{
				Name: "Service B",
			},
		}

		result := mergeAnnotator(a, b)

		assert.NotNil(t, result)
		
		// First input wins for organization and component
		assert.NotNil(t, result.Organization)
		assert.Equal(t, "Organization A", result.Organization.Name)
		assert.NotNil(t, result.Component)
		assert.Equal(t, "Component A", result.Component.Name)

		// Second input fills missing individual and service
		assert.NotNil(t, result.Individual)
		assert.Equal(t, "John Doe", result.Individual.Name)
		assert.NotNil(t, result.Service)
		assert.Equal(t, "Service B", result.Service.Name)
	})

	t.Run("merge annotators with overlapping types", func(t *testing.T) {
		a := &cyclonedx.Annotator{
			Organization: &cyclonedx.OrganizationalEntity{
				Name: "Organization A",
			},
			Individual: &cyclonedx.OrganizationalContact{
				Name: "Jane Smith",
			},
		}
		b := &cyclonedx.Annotator{
			Organization: &cyclonedx.OrganizationalEntity{
				Name: "Organization B", // Should not override
			},
			Individual: &cyclonedx.OrganizationalContact{
				Name: "John Doe", // Should not override
			},
		}

		result := mergeAnnotator(a, b)

		assert.NotNil(t, result)
		
		// First input wins for all fields
		assert.NotNil(t, result.Organization)
		assert.Equal(t, "Organization A", result.Organization.Name)
		assert.NotNil(t, result.Individual)
		assert.Equal(t, "Jane Smith", result.Individual.Name)
		
		// No other fields should be set
		assert.Nil(t, result.Component)
		assert.Nil(t, result.Service)
	})

	t.Run("merge with nil annotators", func(t *testing.T) {
		a := &cyclonedx.Annotator{
			Organization: &cyclonedx.OrganizationalEntity{
				Name: "Organization A",
			},
		}

		result1 := mergeAnnotator(a, nil)
		assert.NotNil(t, result1)
		assert.NotNil(t, result1.Organization)
		assert.Equal(t, "Organization A", result1.Organization.Name)

		result2 := mergeAnnotator(nil, a)
		assert.NotNil(t, result2)
		assert.NotNil(t, result2.Organization)
		assert.Equal(t, "Organization A", result2.Organization.Name)

		result3 := mergeAnnotator(nil, nil)
		assert.Nil(t, result3)
	})
}

func TestMergeAnnotationSlice_Immutability(t *testing.T) {
	t.Run("original slices are not modified", func(t *testing.T) {
		originalA := &[]cyclonedx.Annotation{
			{
				BOMRef:    "annotation-a",
				Timestamp: "2023-01-01T00:00:00Z",
				Text:      "Original annotation",
				Subjects:  &[]cyclonedx.BOMReference{"component-1", "component-2"},
				Annotator: &cyclonedx.Annotator{
					Organization: &cyclonedx.OrganizationalEntity{
						Name: "Org A",
					},
				},
			},
		}
		originalB := &[]cyclonedx.Annotation{
			{
				BOMRef:    "annotation-a", // Same BOMRef for merging
				Timestamp: "2023-02-01T00:00:00Z",
				Text:      "Updated annotation",
				Subjects:  &[]cyclonedx.BOMReference{"component-3", "component-4"},
				Annotator: &cyclonedx.Annotator{
					Individual: &cyclonedx.OrganizationalContact{
						Name: "John Doe",
					},
				},
			},
		}

		// Create copies for comparison
		copyA := &[]cyclonedx.Annotation{
			{
				BOMRef:    (*originalA)[0].BOMRef,
				Timestamp: (*originalA)[0].Timestamp,
				Text:      (*originalA)[0].Text,
				Subjects:  &[]cyclonedx.BOMReference{(*(*originalA)[0].Subjects)[0], (*(*originalA)[0].Subjects)[1]},
				Annotator: &cyclonedx.Annotator{
					Organization: &cyclonedx.OrganizationalEntity{
						Name: (*originalA)[0].Annotator.Organization.Name,
					},
				},
			},
		}
		copyB := &[]cyclonedx.Annotation{
			{
				BOMRef:    (*originalB)[0].BOMRef,
				Timestamp: (*originalB)[0].Timestamp,
				Text:      (*originalB)[0].Text,
				Subjects:  &[]cyclonedx.BOMReference{(*(*originalB)[0].Subjects)[0], (*(*originalB)[0].Subjects)[1]},
				Annotator: &cyclonedx.Annotator{
					Individual: &cyclonedx.OrganizationalContact{
						Name: (*originalB)[0].Annotator.Individual.Name,
					},
				},
			},
		}

		result := mergeAnnotationSlice(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, (*copyA)[0].BOMRef, (*originalA)[0].BOMRef)
		assert.Equal(t, (*copyA)[0].Timestamp, (*originalA)[0].Timestamp)
		assert.Equal(t, (*copyA)[0].Text, (*originalA)[0].Text)
		assert.Equal(t, *(*copyA)[0].Subjects, *(*originalA)[0].Subjects)
		assert.Equal(t, (*copyA)[0].Annotator.Organization.Name, (*originalA)[0].Annotator.Organization.Name)

		assert.Equal(t, (*copyB)[0].BOMRef, (*originalB)[0].BOMRef)
		assert.Equal(t, (*copyB)[0].Timestamp, (*originalB)[0].Timestamp)
		assert.Equal(t, (*copyB)[0].Text, (*originalB)[0].Text)
		assert.Equal(t, *(*copyB)[0].Subjects, *(*originalB)[0].Subjects)
		assert.Equal(t, (*copyB)[0].Annotator.Individual.Name, (*originalB)[0].Annotator.Individual.Name)

		// Verify result is merged correctly
		assert.NotNil(t, result)
		assert.Len(t, *result, 1) // One merged annotation
		assert.Equal(t, "annotation-a", (*result)[0].BOMRef)
		assert.Equal(t, "2023-01-01T00:00:00Z", (*result)[0].Timestamp) // First input wins

		// Both subject arrays should be merged in result
		assert.NotNil(t, (*result)[0].Subjects)
		assert.Len(t, *(*result)[0].Subjects, 4) // All unique subjects

		// Both annotator fields should be present in result
		assert.NotNil(t, (*result)[0].Annotator.Organization)
		assert.NotNil(t, (*result)[0].Annotator.Individual)
	})
}