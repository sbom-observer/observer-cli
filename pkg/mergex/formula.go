package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeFormula merges two cyclonedx.Formula structs non-destructively.
// Since BOMRef is a unique identifier, this function assumes both formulas have the same BOMRef.
// For array fields, items from both inputs are combined.
// Returns a new Formula struct without modifying the inputs.
func mergeFormula(a, b cyclonedx.Formula) cyclonedx.Formula {
	result := cyclonedx.Formula{
		BOMRef: a.BOMRef, // Both should have the same BOMRef, use first input
	}

	// Merge array fields
	result.Components = mergeComponentSlice(a.Components, b.Components)
	result.Services = mergeServiceSliceInternal(a.Services, b.Services) // Use internal version to avoid naming conflict
	result.Workflows = mergeWorkflowSlice(a.Workflows, b.Workflows)
	result.Properties = mergePropertySlice(a.Properties, b.Properties)

	return result
}

// mergeFormulaSlice merges two Formula slices non-destructively.
// Formulas with the same BOMRef are merged together.
// Formulas with unique BOMRefs are included as-is.
// Returns a new slice without modifying the inputs.
func mergeFormulaSlice(a, b *[]cyclonedx.Formula) *[]cyclonedx.Formula {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track formulas by BOMRef
	formulaMap := make(map[string]cyclonedx.Formula)

	// First add all formulas from a
	if a != nil {
		for _, formula := range *a {
			formulaMap[formula.BOMRef] = formula
		}
	}

	// Then process formulas from b
	if b != nil {
		for _, formula := range *b {
			if existing, exists := formulaMap[formula.BOMRef]; exists {
				// Merge with existing formula (same BOMRef)
				formulaMap[formula.BOMRef] = mergeFormula(existing, formula)
			} else {
				// Add new formula (unique BOMRef)
				formulaMap[formula.BOMRef] = formula
			}
		}
	}

	if len(formulaMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Formula, 0, len(formulaMap))
	for _, formula := range formulaMap {
		result = append(result, formula)
	}

	return &result
}

// mergeWorkflow merges two cyclonedx.Workflow structs non-destructively.
// Since BOMRef is a unique identifier, this function assumes both workflows have the same BOMRef.
// For non-array fields, the first input takes precedence.
// For array fields, items from both inputs are combined.
// Returns a new Workflow struct without modifying the inputs.
func mergeWorkflow(a, b cyclonedx.Workflow) cyclonedx.Workflow {
	result := cyclonedx.Workflow{
		BOMRef: a.BOMRef, // Both should have the same BOMRef, use first input
	}

	// Fill empty simple fields from b where a is empty
	if a.UID == "" {
		result.UID = b.UID
	} else {
		result.UID = a.UID
	}
	if a.Name == "" {
		result.Name = b.Name
	} else {
		result.Name = a.Name
	}
	if a.Description == "" {
		result.Description = b.Description
	} else {
		result.Description = a.Description
	}
	if a.TimeStart == "" {
		result.TimeStart = b.TimeStart
	} else {
		result.TimeStart = a.TimeStart
	}
	if a.TimeEnd == "" {
		result.TimeEnd = b.TimeEnd
	} else {
		result.TimeEnd = a.TimeEnd
	}

	// Merge complex fields - first input wins
	if a.Trigger != nil {
		result.Trigger = copyTaskTrigger(a.Trigger)
	} else {
		result.Trigger = copyTaskTrigger(b.Trigger)
	}

	// Merge array fields
	result.ResourceReferences = mergeResourceReferenceChoiceSlice(a.ResourceReferences, b.ResourceReferences)
	result.Tasks = mergeTaskSlice(a.Tasks, b.Tasks)
	result.TaskDependencies = mergeDependencySlice(a.TaskDependencies, b.TaskDependencies)
	result.TaskTypes = mergeTaskTypeSlice(a.TaskTypes, b.TaskTypes)
	result.Steps = mergeTaskStepSlice(a.Steps, b.Steps)
	result.Inputs = mergeTaskInputSlice(a.Inputs, b.Inputs)
	result.Outputs = mergeTaskOutputSlice(a.Outputs, b.Outputs)
	result.Workspaces = mergeTaskWorkspaceSlice(a.Workspaces, b.Workspaces)

	return result
}

// mergeWorkflowSlice merges two Workflow slices non-destructively.
// Workflows with the same BOMRef are merged together.
// Workflows with unique BOMRefs are included as-is.
// Returns a new slice without modifying the inputs.
func mergeWorkflowSlice(a, b *[]cyclonedx.Workflow) *[]cyclonedx.Workflow {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track workflows by BOMRef
	workflowMap := make(map[string]cyclonedx.Workflow)

	// First add all workflows from a
	if a != nil {
		for _, workflow := range *a {
			workflowMap[workflow.BOMRef] = workflow
		}
	}

	// Then process workflows from b
	if b != nil {
		for _, workflow := range *b {
			if existing, exists := workflowMap[workflow.BOMRef]; exists {
				// Merge with existing workflow (same BOMRef)
				workflowMap[workflow.BOMRef] = mergeWorkflow(existing, workflow)
			} else {
				// Add new workflow (unique BOMRef)
				workflowMap[workflow.BOMRef] = workflow
			}
		}
	}

	if len(workflowMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Workflow, 0, len(workflowMap))
	for _, workflow := range workflowMap {
		result = append(result, workflow)
	}

	return &result
}

// Helper copy and merge functions for complex types
// These are simplified implementations - full deep copy would be needed in production

func copyTaskTrigger(trigger *cyclonedx.TaskTrigger) *cyclonedx.TaskTrigger {
	if trigger == nil {
		return nil
	}
	copy := *trigger
	return &copy
}

// Helper merge functions for array types - simple concatenation for now

func mergeResourceReferenceChoiceSlice(a, b *[]cyclonedx.ResourceReferenceChoice) *[]cyclonedx.ResourceReferenceChoice {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.ResourceReferenceChoice

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

func mergeTaskSlice(a, b *[]cyclonedx.Task) *[]cyclonedx.Task {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Task

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

func mergeTaskTypeSlice(a, b *[]cyclonedx.TaskType) *[]cyclonedx.TaskType {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.TaskType

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

func mergeTaskStepSlice(a, b *[]cyclonedx.TaskStep) *[]cyclonedx.TaskStep {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.TaskStep

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

func mergeTaskInputSlice(a, b *[]cyclonedx.TaskInput) *[]cyclonedx.TaskInput {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.TaskInput

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

func mergeTaskOutputSlice(a, b *[]cyclonedx.TaskOutput) *[]cyclonedx.TaskOutput {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.TaskOutput

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

func mergeTaskWorkspaceSlice(a, b *[]cyclonedx.TaskWorkspace) *[]cyclonedx.TaskWorkspace {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.TaskWorkspace

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

func copyFormulaSlice(formulas *[]cyclonedx.Formula) *[]cyclonedx.Formula {
	if formulas == nil {
		return nil
	}
	result := make([]cyclonedx.Formula, len(*formulas))
	copy(result, *formulas)
	return &result
}