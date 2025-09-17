package mergex

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeFormula(t *testing.T) {
	t.Run("merge formulas with same BOMRef", func(t *testing.T) {
		a := cyclonedx.Formula{
			BOMRef: "formula-a",
			Components: &[]cyclonedx.Component{
				{BOMRef: "comp-1", Name: "Component 1"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "production"},
			},
		}
		b := cyclonedx.Formula{
			BOMRef: "formula-a",
			Services: &[]cyclonedx.Service{
				{BOMRef: "svc-1", Name: "Service 1"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "staging"}, // duplicate key - first should win
				{Name: "owner", Value: "team-b"}, // new key
			},
		}

		result := mergeFormula(a, b)

		assert.Equal(t, "formula-a", result.BOMRef)

		// Components from first should be preserved
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "comp-1", (*result.Components)[0].BOMRef)
		assert.Equal(t, "Component 1", (*result.Components)[0].Name)

		// Services from second should be included
		assert.NotNil(t, result.Services)
		assert.Len(t, *result.Services, 1)
		assert.Equal(t, "svc-1", (*result.Services)[0].BOMRef)
		assert.Equal(t, "Service 1", (*result.Services)[0].Name)

		// Properties should be merged by key
		assert.NotNil(t, result.Properties)
		assert.Len(t, *result.Properties, 2) // 2 unique keys

		propMap := make(map[string]string)
		for _, prop := range *result.Properties {
			propMap[prop.Name] = prop.Value
		}
		assert.Equal(t, "production", propMap["env"]) // First input wins
		assert.Equal(t, "team-b", propMap["owner"])
	})

	t.Run("merge formulas with workflows", func(t *testing.T) {
		a := cyclonedx.Formula{
			BOMRef: "formula-a",
			Workflows: &[]cyclonedx.Workflow{
				{BOMRef: "wf-1", Name: "Workflow 1"},
			},
		}
		b := cyclonedx.Formula{
			BOMRef: "formula-a",
			Workflows: &[]cyclonedx.Workflow{
				{BOMRef: "wf-2", Name: "Workflow 2"},
			},
		}

		result := mergeFormula(a, b)

		assert.Equal(t, "formula-a", result.BOMRef)

		// Workflows should be concatenated
		assert.NotNil(t, result.Workflows)
		assert.Len(t, *result.Workflows, 2)
		assert.Equal(t, "wf-1", (*result.Workflows)[0].BOMRef)
		assert.Equal(t, "Workflow 1", (*result.Workflows)[0].Name)
		assert.Equal(t, "wf-2", (*result.Workflows)[1].BOMRef)
		assert.Equal(t, "Workflow 2", (*result.Workflows)[1].Name)
	})

	t.Run("merge formulas with nil arrays", func(t *testing.T) {
		a := cyclonedx.Formula{
			BOMRef: "formula-a",
			Components: &[]cyclonedx.Component{
				{BOMRef: "comp-1", Name: "Component 1"},
			},
			Services: nil,
		}
		b := cyclonedx.Formula{
			BOMRef: "formula-a",
			Components: nil,
			Services: &[]cyclonedx.Service{
				{BOMRef: "svc-1", Name: "Service 1"},
			},
		}

		result := mergeFormula(a, b)

		assert.Equal(t, "formula-a", result.BOMRef)

		// Components from first should be preserved
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "comp-1", (*result.Components)[0].BOMRef)

		// Services from second should be included
		assert.NotNil(t, result.Services)
		assert.Len(t, *result.Services, 1)
		assert.Equal(t, "svc-1", (*result.Services)[0].BOMRef)
	})
}

func TestMergeFormulaSlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeFormulaSlice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.Formula{
			{
				BOMRef: "formula-b",
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp-1", Name: "Component 1"},
				},
			},
		}

		result := mergeFormulaSlice(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "formula-b", (*result)[0].BOMRef)
		assert.NotNil(t, (*result)[0].Components)
		assert.Equal(t, "comp-1", (*(*result)[0].Components)[0].BOMRef)
	})

	t.Run("merge slices with no overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Formula{
			{
				BOMRef: "formula-a",
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp-1", Name: "Component 1"},
				},
			},
		}
		b := &[]cyclonedx.Formula{
			{
				BOMRef: "formula-b",
				Services: &[]cyclonedx.Service{
					{BOMRef: "svc-1", Name: "Service 1"},
				},
			},
		}

		result := mergeFormulaSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Convert to map for easier testing since order is not guaranteed
		formulaMap := make(map[string]cyclonedx.Formula)
		for _, formula := range *result {
			formulaMap[formula.BOMRef] = formula
		}

		assert.NotNil(t, formulaMap["formula-a"].Components)
		assert.Equal(t, "comp-1", (*formulaMap["formula-a"].Components)[0].BOMRef)

		assert.NotNil(t, formulaMap["formula-b"].Services)
		assert.Equal(t, "svc-1", (*formulaMap["formula-b"].Services)[0].BOMRef)
	})

	t.Run("merge slices with overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Formula{
			{
				BOMRef: "formula-a",
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp-1", Name: "Component 1"},
				},
				Properties: &[]cyclonedx.Property{
					{Name: "env", Value: "production"},
				},
			},
			{
				BOMRef: "formula-b",
				Services: &[]cyclonedx.Service{
					{BOMRef: "svc-1", Name: "Service 1"},
				},
			},
		}
		b := &[]cyclonedx.Formula{
			{
				BOMRef: "formula-a", // Same BOMRef as first
				Services: &[]cyclonedx.Service{
					{BOMRef: "svc-2", Name: "Service 2"},
				},
				Properties: &[]cyclonedx.Property{
					{Name: "env", Value: "staging"}, // duplicate key - first should win
					{Name: "owner", Value: "team-a"}, // new key
				},
			},
			{
				BOMRef: "formula-c",
				Workflows: &[]cyclonedx.Workflow{
					{BOMRef: "wf-1", Name: "Workflow 1"},
				},
			},
		}

		result := mergeFormulaSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // formula-a merged, formula-b and formula-c separate

		// Convert to map for easier testing since order is not guaranteed
		formulaMap := make(map[string]cyclonedx.Formula)
		for _, formula := range *result {
			formulaMap[formula.BOMRef] = formula
		}

		// formula-a should have merged arrays
		assert.NotNil(t, formulaMap["formula-a"].Components)
		assert.Len(t, *formulaMap["formula-a"].Components, 1)
		assert.Equal(t, "comp-1", (*formulaMap["formula-a"].Components)[0].BOMRef)

		assert.NotNil(t, formulaMap["formula-a"].Services)
		assert.Len(t, *formulaMap["formula-a"].Services, 1)
		assert.Equal(t, "svc-2", (*formulaMap["formula-a"].Services)[0].BOMRef)

		// Properties should be merged by key
		propMap := make(map[string]string)
		for _, prop := range *formulaMap["formula-a"].Properties {
			propMap[prop.Name] = prop.Value
		}
		assert.Equal(t, "production", propMap["env"]) // First input wins
		assert.Equal(t, "team-a", propMap["owner"])

		// formula-b should remain unchanged
		assert.NotNil(t, formulaMap["formula-b"].Services)
		assert.Equal(t, "svc-1", (*formulaMap["formula-b"].Services)[0].BOMRef)

		// formula-c should be added as-is
		assert.NotNil(t, formulaMap["formula-c"].Workflows)
		assert.Equal(t, "wf-1", (*formulaMap["formula-c"].Workflows)[0].BOMRef)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.Formula{}
		b := &[]cyclonedx.Formula{}

		result := mergeFormulaSlice(a, b)

		assert.Nil(t, result)
	})
}

func TestMergeWorkflow(t *testing.T) {
	t.Run("merge workflows with same BOMRef", func(t *testing.T) {
		a := cyclonedx.Workflow{
			BOMRef:      "workflow-a",
			UID:         "uid-a",
			Name:        "Workflow A",
			Description: "Original workflow",
			TimeStart:   "2023-01-01T00:00:00Z",
			Tasks: &[]cyclonedx.Task{
				{BOMRef: "task-1", Name: "Task 1"},
			},
		}
		b := cyclonedx.Workflow{
			BOMRef:      "workflow-a",
			UID:         "uid-b", // Should not override first
			Name:        "Workflow B", // Should not override first
			Description: "Updated workflow", // Should not override first
			TimeEnd:     "2023-01-01T01:00:00Z", // Should be filled from second
			Tasks: &[]cyclonedx.Task{
				{BOMRef: "task-2", Name: "Task 2"},
			},
		}

		result := mergeWorkflow(a, b)

		assert.Equal(t, "workflow-a", result.BOMRef)
		assert.Equal(t, "uid-a", result.UID) // First input wins
		assert.Equal(t, "Workflow A", result.Name) // First input wins
		assert.Equal(t, "Original workflow", result.Description) // First input wins
		assert.Equal(t, "2023-01-01T00:00:00Z", result.TimeStart) // From first
		assert.Equal(t, "2023-01-01T01:00:00Z", result.TimeEnd) // Filled from second

		// Tasks should be concatenated
		assert.NotNil(t, result.Tasks)
		assert.Len(t, *result.Tasks, 2)
		assert.Equal(t, "task-1", (*result.Tasks)[0].BOMRef)
		assert.Equal(t, "Task 1", (*result.Tasks)[0].Name)
		assert.Equal(t, "task-2", (*result.Tasks)[1].BOMRef)
		assert.Equal(t, "Task 2", (*result.Tasks)[1].Name)
	})

	t.Run("merge workflows with empty fields", func(t *testing.T) {
		a := cyclonedx.Workflow{
			BOMRef: "workflow-a",
			Name:   "Workflow A",
			// UID empty - should be filled from b
			// Description empty - should be filled from b
			Tasks: &[]cyclonedx.Task{
				{BOMRef: "task-1"},
			},
		}
		b := cyclonedx.Workflow{
			BOMRef:      "workflow-a",
			UID:         "uid-b", // Should fill empty field
			Description: "Filled from second", // Should fill empty field
			Tasks:       nil,
		}

		result := mergeWorkflow(a, b)

		assert.Equal(t, "workflow-a", result.BOMRef)
		assert.Equal(t, "Workflow A", result.Name) // First input wins
		assert.Equal(t, "uid-b", result.UID) // Filled from second
		assert.Equal(t, "Filled from second", result.Description) // Filled from second

		// Tasks from first should be preserved
		assert.NotNil(t, result.Tasks)
		assert.Len(t, *result.Tasks, 1)
		assert.Equal(t, "task-1", (*result.Tasks)[0].BOMRef)
	})

	t.Run("merge workflows with nil arrays", func(t *testing.T) {
		a := cyclonedx.Workflow{
			BOMRef: "workflow-a",
			Name:   "Workflow A",
			Tasks: &[]cyclonedx.Task{
				{BOMRef: "task-1"},
			},
			Inputs: nil,
		}
		b := cyclonedx.Workflow{
			BOMRef: "workflow-a",
			Name:   "Workflow B",
			Tasks:  nil,
			Inputs: &[]cyclonedx.TaskInput{
				{Source: &cyclonedx.ResourceReferenceChoice{Ref: "input-1"}},
			},
		}

		result := mergeWorkflow(a, b)

		assert.Equal(t, "workflow-a", result.BOMRef)
		assert.Equal(t, "Workflow A", result.Name) // First input wins

		// Tasks from first should be preserved
		assert.NotNil(t, result.Tasks)
		assert.Len(t, *result.Tasks, 1)
		assert.Equal(t, "task-1", (*result.Tasks)[0].BOMRef)

		// Inputs from second should be included
		assert.NotNil(t, result.Inputs)
		assert.Len(t, *result.Inputs, 1)
		assert.Equal(t, "input-1", (*result.Inputs)[0].Source.Ref)
	})
}

func TestMergeWorkflowSlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeWorkflowSlice(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.Workflow{
			{
				BOMRef: "workflow-b",
				Name:   "Workflow B",
				Tasks: &[]cyclonedx.Task{
					{BOMRef: "task-1", Name: "Task 1"},
				},
			},
		}

		result := mergeWorkflowSlice(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "workflow-b", (*result)[0].BOMRef)
		assert.Equal(t, "Workflow B", (*result)[0].Name)
	})

	t.Run("merge slices with overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Workflow{
			{
				BOMRef:      "workflow-a",
				Name:        "Workflow A",
				Description: "Original description",
				Tasks: &[]cyclonedx.Task{
					{BOMRef: "task-1", Name: "Task 1"},
				},
			},
		}
		b := &[]cyclonedx.Workflow{
			{
				BOMRef:      "workflow-a", // Same BOMRef
				Name:        "Workflow A Updated", // Should not override
				Description: "Updated description", // Should not override
				TimeEnd:     "2023-01-01T01:00:00Z", // Should be filled
				Tasks: &[]cyclonedx.Task{
					{BOMRef: "task-2", Name: "Task 2"},
				},
			},
		}

		result := mergeWorkflowSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1) // One merged workflow

		workflow := (*result)[0]
		assert.Equal(t, "workflow-a", workflow.BOMRef)
		assert.Equal(t, "Workflow A", workflow.Name) // First input wins
		assert.Equal(t, "Original description", workflow.Description) // First input wins
		assert.Equal(t, "2023-01-01T01:00:00Z", workflow.TimeEnd) // Filled from second

		// Tasks should be concatenated
		assert.NotNil(t, workflow.Tasks)
		assert.Len(t, *workflow.Tasks, 2)
		assert.Equal(t, "task-1", (*workflow.Tasks)[0].BOMRef)
		assert.Equal(t, "task-2", (*workflow.Tasks)[1].BOMRef)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.Workflow{}
		b := &[]cyclonedx.Workflow{}

		result := mergeWorkflowSlice(a, b)

		assert.Nil(t, result)
	})
}

func TestMergeTaskArrays(t *testing.T) {
	t.Run("merge task slices", func(t *testing.T) {
		a := &[]cyclonedx.Task{
			{BOMRef: "task-1", Name: "Task 1"},
			{BOMRef: "task-2", Name: "Task 2"},
		}
		b := &[]cyclonedx.Task{
			{BOMRef: "task-3", Name: "Task 3"},
		}

		result := mergeTaskSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3)
		assert.Equal(t, "task-1", (*result)[0].BOMRef)
		assert.Equal(t, "Task 1", (*result)[0].Name)
		assert.Equal(t, "task-2", (*result)[1].BOMRef)
		assert.Equal(t, "Task 2", (*result)[1].Name)
		assert.Equal(t, "task-3", (*result)[2].BOMRef)
		assert.Equal(t, "Task 3", (*result)[2].Name)
	})

	t.Run("merge with nil slices", func(t *testing.T) {
		a := &[]cyclonedx.Task{
			{BOMRef: "task-1"},
		}

		result1 := mergeTaskSlice(a, nil)
		assert.NotNil(t, result1)
		assert.Len(t, *result1, 1)
		assert.Equal(t, "task-1", (*result1)[0].BOMRef)

		result2 := mergeTaskSlice(nil, a)
		assert.NotNil(t, result2)
		assert.Len(t, *result2, 1)
		assert.Equal(t, "task-1", (*result2)[0].BOMRef)

		result3 := mergeTaskSlice(nil, nil)
		assert.Nil(t, result3)
	})
}

func TestMergeFormulaSlice_Immutability(t *testing.T) {
	t.Run("original slices are not modified", func(t *testing.T) {
		originalA := &[]cyclonedx.Formula{
			{
				BOMRef: "formula-a",
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp-1", Name: "Component 1"},
				},
				Properties: &[]cyclonedx.Property{
					{Name: "env", Value: "production"},
				},
			},
		}
		originalB := &[]cyclonedx.Formula{
			{
				BOMRef: "formula-a", // Same BOMRef for merging
				Services: &[]cyclonedx.Service{
					{BOMRef: "svc-1", Name: "Service 1"},
				},
				Properties: &[]cyclonedx.Property{
					{Name: "owner", Value: "team-a"},
				},
			},
		}

		// Create copies for comparison
		copyA := &[]cyclonedx.Formula{
			{
				BOMRef: (*originalA)[0].BOMRef,
				Components: &[]cyclonedx.Component{
					{BOMRef: (*(*originalA)[0].Components)[0].BOMRef, Name: (*(*originalA)[0].Components)[0].Name},
				},
				Properties: &[]cyclonedx.Property{
					{Name: (*(*originalA)[0].Properties)[0].Name, Value: (*(*originalA)[0].Properties)[0].Value},
				},
			},
		}
		copyB := &[]cyclonedx.Formula{
			{
				BOMRef: (*originalB)[0].BOMRef,
				Services: &[]cyclonedx.Service{
					{BOMRef: (*(*originalB)[0].Services)[0].BOMRef, Name: (*(*originalB)[0].Services)[0].Name},
				},
				Properties: &[]cyclonedx.Property{
					{Name: (*(*originalB)[0].Properties)[0].Name, Value: (*(*originalB)[0].Properties)[0].Value},
				},
			},
		}

		result := mergeFormulaSlice(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, (*copyA)[0].BOMRef, (*originalA)[0].BOMRef)
		assert.Equal(t, (*(*copyA)[0].Components)[0].BOMRef, (*(*originalA)[0].Components)[0].BOMRef)
		assert.Equal(t, (*(*copyA)[0].Properties)[0].Name, (*(*originalA)[0].Properties)[0].Name)

		assert.Equal(t, (*copyB)[0].BOMRef, (*originalB)[0].BOMRef)
		assert.Equal(t, (*(*copyB)[0].Services)[0].BOMRef, (*(*originalB)[0].Services)[0].BOMRef)
		assert.Equal(t, (*(*copyB)[0].Properties)[0].Name, (*(*originalB)[0].Properties)[0].Name)

		// Verify result is merged correctly
		assert.NotNil(t, result)
		assert.Len(t, *result, 1) // One merged formula
		assert.Equal(t, "formula-a", (*result)[0].BOMRef)

		// Both component and service arrays should be present in result
		assert.NotNil(t, (*result)[0].Components)
		assert.Len(t, *(*result)[0].Components, 1)
		assert.NotNil(t, (*result)[0].Services)
		assert.Len(t, *(*result)[0].Services, 1)

		// Both property arrays should be merged in result
		assert.NotNil(t, (*result)[0].Properties)
		assert.Len(t, *(*result)[0].Properties, 2) // Both unique properties
	})
}