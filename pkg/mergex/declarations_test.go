package mergex

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeDeclarations(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeDeclarations(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &cyclonedx.Declarations{
			Assessors: &[]cyclonedx.Assessor{
				{
					BOMRef:     "assessor-1",
					ThirdParty: true,
				},
			},
			Targets: &cyclonedx.Targets{
				Organizations: &[]cyclonedx.OrganizationalEntity{
					{Name: "Org B"},
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement B",
			},
		}

		result := mergeDeclarations(nil, b)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Assessors)
		assert.Len(t, *result.Assessors, 1)
		assert.Equal(t, "assessor-1", string((*result.Assessors)[0].BOMRef))
		assert.True(t, (*result.Assessors)[0].ThirdParty)

		assert.NotNil(t, result.Targets)
		assert.NotNil(t, result.Targets.Organizations)
		assert.Equal(t, "Org B", (*result.Targets.Organizations)[0].Name)

		assert.NotNil(t, result.Affirmation)
		assert.Equal(t, "Statement B", result.Affirmation.Statement)
	})

	t.Run("first has values, second nil", func(t *testing.T) {
		a := &cyclonedx.Declarations{
			Claims: &[]cyclonedx.Claim{
				{
					BOMRef: "claim-1",
				},
			},
			Targets: &cyclonedx.Targets{
				Components: &[]cyclonedx.Component{
					{Name: "Component A"},
				},
			},
		}

		result := mergeDeclarations(a, nil)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Claims)
		assert.Len(t, *result.Claims, 1)
		assert.Equal(t, "claim-1", string((*result.Claims)[0].BOMRef))

		assert.NotNil(t, result.Targets)
		assert.NotNil(t, result.Targets.Components)
		assert.Equal(t, "Component A", (*result.Targets.Components)[0].Name)
	})

	t.Run("merge declarations with different array fields", func(t *testing.T) {
		a := &cyclonedx.Declarations{
			Assessors: &[]cyclonedx.Assessor{
				{
					BOMRef:     "assessor-a",
					ThirdParty: true,
				},
			},
			Attestations: &[]cyclonedx.Attestation{
				{
					Summary: "Attestation A",
				},
			},
			Targets: &cyclonedx.Targets{
				Organizations: &[]cyclonedx.OrganizationalEntity{
					{Name: "Org A"},
				},
			},
		}
		b := &cyclonedx.Declarations{
			Claims: &[]cyclonedx.Claim{
				{
					BOMRef: "claim-b",
				},
			},
			Evidence: &[]cyclonedx.DeclarationEvidence{
				{
					BOMRef:      "evidence-b",
					Description: "Evidence B",
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement B",
			},
		}

		result := mergeDeclarations(a, b)

		assert.NotNil(t, result)

		// Arrays from both inputs should be present
		assert.NotNil(t, result.Assessors)
		assert.Len(t, *result.Assessors, 1)
		assert.Equal(t, "assessor-a", string((*result.Assessors)[0].BOMRef))

		assert.NotNil(t, result.Attestations)
		assert.Len(t, *result.Attestations, 1)
		assert.Equal(t, "Attestation A", (*result.Attestations)[0].Summary)

		assert.NotNil(t, result.Claims)
		assert.Len(t, *result.Claims, 1)
		assert.Equal(t, "claim-b", string((*result.Claims)[0].BOMRef))

		assert.NotNil(t, result.Evidence)
		assert.Len(t, *result.Evidence, 1)
		assert.Equal(t, "evidence-b", (*result.Evidence)[0].BOMRef)
		assert.Equal(t, "Evidence B", (*result.Evidence)[0].Description)

		// Complex fields - first input wins
		assert.NotNil(t, result.Targets)
		assert.NotNil(t, result.Targets.Organizations)
		assert.Equal(t, "Org A", (*result.Targets.Organizations)[0].Name)

		// Second input fills missing complex fields
		assert.NotNil(t, result.Affirmation)
		assert.Equal(t, "Statement B", result.Affirmation.Statement)
	})

	t.Run("merge declarations with overlapping array fields", func(t *testing.T) {
		a := &cyclonedx.Declarations{
			Assessors: &[]cyclonedx.Assessor{
				{
					BOMRef:     "assessor-a",
					ThirdParty: true,
				},
			},
			Claims: &[]cyclonedx.Claim{
				{
					BOMRef: "claim-a",
				},
			},
			Targets: &cyclonedx.Targets{
				Organizations: &[]cyclonedx.OrganizationalEntity{
					{Name: "Org A"},
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement A",
			},
		}
		b := &cyclonedx.Declarations{
			Assessors: &[]cyclonedx.Assessor{
				{
					BOMRef:     "assessor-b",
					ThirdParty: false,
				},
			},
			Claims: &[]cyclonedx.Claim{
				{
					BOMRef: "claim-b",
				},
			},
			Targets: &cyclonedx.Targets{
				Components: &[]cyclonedx.Component{
					{Name: "Component B"},
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement B", // Should not override first
			},
		}

		result := mergeDeclarations(a, b)

		assert.NotNil(t, result)

		// Arrays should be concatenated
		assert.NotNil(t, result.Assessors)
		assert.Len(t, *result.Assessors, 2)
		assert.Equal(t, "assessor-a", string((*result.Assessors)[0].BOMRef))
		assert.True(t, (*result.Assessors)[0].ThirdParty)
		assert.Equal(t, "assessor-b", string((*result.Assessors)[1].BOMRef))
		assert.False(t, (*result.Assessors)[1].ThirdParty)

		assert.NotNil(t, result.Claims)
		assert.Len(t, *result.Claims, 2)
		assert.Equal(t, "claim-a", string((*result.Claims)[0].BOMRef))
		assert.Equal(t, "claim-b", string((*result.Claims)[1].BOMRef))

		// Complex fields - first input wins
		assert.NotNil(t, result.Targets)
		assert.NotNil(t, result.Targets.Organizations)
		assert.Equal(t, "Org A", (*result.Targets.Organizations)[0].Name)
		assert.Nil(t, result.Targets.Components) // Only from first input

		assert.NotNil(t, result.Affirmation)
		assert.Equal(t, "Statement A", result.Affirmation.Statement) // First input wins
	})

	t.Run("merge declarations with empty arrays", func(t *testing.T) {
		a := &cyclonedx.Declarations{
			Assessors: &[]cyclonedx.Assessor{},
			Claims:    &[]cyclonedx.Claim{},
		}
		b := &cyclonedx.Declarations{
			Attestations: &[]cyclonedx.Attestation{},
			Evidence:     &[]cyclonedx.DeclarationEvidence{},
		}

		result := mergeDeclarations(a, b)

		assert.NotNil(t, result)
		assert.Nil(t, result.Assessors)    // Empty arrays result in nil
		assert.Nil(t, result.Claims)       // Empty arrays result in nil
		assert.Nil(t, result.Attestations) // Empty arrays result in nil
		assert.Nil(t, result.Evidence)     // Empty arrays result in nil
	})
}

func TestMergeDeclarations_ComplexFields(t *testing.T) {
	t.Run("merge targets with different target types", func(t *testing.T) {
		a := &cyclonedx.Declarations{
			Targets: &cyclonedx.Targets{
				Organizations: &[]cyclonedx.OrganizationalEntity{
					{Name: "Org A"},
				},
				Components: &[]cyclonedx.Component{
					{Name: "Component A"},
				},
			},
		}
		b := &cyclonedx.Declarations{
			Targets: &cyclonedx.Targets{
				Services: &[]cyclonedx.Service{
					{Name: "Service B"},
				},
			},
		}

		result := mergeDeclarations(a, b)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Targets)

		// First input wins completely
		assert.NotNil(t, result.Targets.Organizations)
		assert.Equal(t, "Org A", (*result.Targets.Organizations)[0].Name)
		assert.NotNil(t, result.Targets.Components)
		assert.Equal(t, "Component A", (*result.Targets.Components)[0].Name)
		assert.Nil(t, result.Targets.Services) // Not from first input
	})

	t.Run("merge affirmations", func(t *testing.T) {
		a := &cyclonedx.Declarations{
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement A",
				Signatories: &[]cyclonedx.Signatory{
					{Name: "Signatory A"},
				},
			},
		}
		b := &cyclonedx.Declarations{
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement B", // Should not override
				Signatories: &[]cyclonedx.Signatory{
					{Name: "Signatory B"}, // Should not be included
				},
			},
		}

		result := mergeDeclarations(a, b)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Affirmation)

		// First input wins completely
		assert.Equal(t, "Statement A", result.Affirmation.Statement)
		assert.NotNil(t, result.Affirmation.Signatories)
		assert.Len(t, *result.Affirmation.Signatories, 1)
		assert.Equal(t, "Signatory A", (*result.Affirmation.Signatories)[0].Name)
	})
}

func TestMergeDeclarations_ArrayMerging(t *testing.T) {
	t.Run("merge assessor slices", func(t *testing.T) {
		a := &[]cyclonedx.Assessor{
			{BOMRef: "assessor-1", ThirdParty: true},
			{BOMRef: "assessor-2", ThirdParty: false},
		}
		b := &[]cyclonedx.Assessor{
			{BOMRef: "assessor-3", ThirdParty: true},
		}

		result := mergeAssessorSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3)
		assert.Equal(t, "assessor-1", string((*result)[0].BOMRef))
		assert.Equal(t, "assessor-2", string((*result)[1].BOMRef))
		assert.Equal(t, "assessor-3", string((*result)[2].BOMRef))
	})

	t.Run("merge claim slices", func(t *testing.T) {
		a := &[]cyclonedx.Claim{
			{BOMRef: "claim-1"},
		}
		b := &[]cyclonedx.Claim{
			{BOMRef: "claim-2"},
			{BOMRef: "claim-3"},
		}

		result := mergeClaimSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3)
		assert.Equal(t, "claim-1", string((*result)[0].BOMRef))
		assert.Equal(t, "claim-2", string((*result)[1].BOMRef))
		assert.Equal(t, "claim-3", string((*result)[2].BOMRef))
	})

	t.Run("merge evidence slices", func(t *testing.T) {
		a := &[]cyclonedx.DeclarationEvidence{
			{BOMRef: "evidence-1", Description: "Evidence A"},
		}
		b := &[]cyclonedx.DeclarationEvidence{
			{BOMRef: "evidence-2", Description: "Evidence B"},
		}

		result := mergeDeclarationEvidenceSlice(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)
		assert.Equal(t, "evidence-1", (*result)[0].BOMRef)
		assert.Equal(t, "Evidence A", (*result)[0].Description)
		assert.Equal(t, "evidence-2", (*result)[1].BOMRef)
		assert.Equal(t, "Evidence B", (*result)[1].Description)
	})

	t.Run("merge with nil slices", func(t *testing.T) {
		a := &[]cyclonedx.Assessor{
			{BOMRef: "assessor-1"},
		}

		result1 := mergeAssessorSlice(a, nil)
		assert.NotNil(t, result1)
		assert.Len(t, *result1, 1)
		assert.Equal(t, "assessor-1", string((*result1)[0].BOMRef))

		result2 := mergeAssessorSlice(nil, a)
		assert.NotNil(t, result2)
		assert.Len(t, *result2, 1)
		assert.Equal(t, "assessor-1", string((*result2)[0].BOMRef))

		result3 := mergeAssessorSlice(nil, nil)
		assert.Nil(t, result3)
	})
}

func TestMergeDeclarations_Immutability(t *testing.T) {
	t.Run("original declarations are not modified", func(t *testing.T) {
		originalA := &cyclonedx.Declarations{
			Assessors: &[]cyclonedx.Assessor{
				{BOMRef: "assessor-a", ThirdParty: true},
			},
			Targets: &cyclonedx.Targets{
				Organizations: &[]cyclonedx.OrganizationalEntity{
					{Name: "Org A"},
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement A",
			},
		}
		originalB := &cyclonedx.Declarations{
			Claims: &[]cyclonedx.Claim{
				{BOMRef: "claim-b"},
			},
			Targets: &cyclonedx.Targets{
				Components: &[]cyclonedx.Component{
					{Name: "Component B"},
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: "Statement B",
			},
		}

		// Create copies for comparison
		copyA := &cyclonedx.Declarations{
			Assessors: &[]cyclonedx.Assessor{
				{BOMRef: (*originalA.Assessors)[0].BOMRef, ThirdParty: (*originalA.Assessors)[0].ThirdParty},
			},
			Targets: &cyclonedx.Targets{
				Organizations: &[]cyclonedx.OrganizationalEntity{
					{Name: (*originalA.Targets.Organizations)[0].Name},
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: originalA.Affirmation.Statement,
			},
		}
		copyB := &cyclonedx.Declarations{
			Claims: &[]cyclonedx.Claim{
				{BOMRef: (*originalB.Claims)[0].BOMRef},
			},
			Targets: &cyclonedx.Targets{
				Components: &[]cyclonedx.Component{
					{Name: (*originalB.Targets.Components)[0].Name},
				},
			},
			Affirmation: &cyclonedx.Affirmation{
				Statement: originalB.Affirmation.Statement,
			},
		}

		result := mergeDeclarations(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, (*copyA.Assessors)[0].BOMRef, (*originalA.Assessors)[0].BOMRef)
		assert.Equal(t, (*copyA.Assessors)[0].ThirdParty, (*originalA.Assessors)[0].ThirdParty)
		assert.Equal(t, (*copyA.Targets.Organizations)[0].Name, (*originalA.Targets.Organizations)[0].Name)
		assert.Equal(t, copyA.Affirmation.Statement, originalA.Affirmation.Statement)

		assert.Equal(t, (*copyB.Claims)[0].BOMRef, (*originalB.Claims)[0].BOMRef)
		assert.Equal(t, (*copyB.Targets.Components)[0].Name, (*originalB.Targets.Components)[0].Name)
		assert.Equal(t, copyB.Affirmation.Statement, originalB.Affirmation.Statement)

		// Verify result is merged correctly
		assert.NotNil(t, result)
		assert.NotNil(t, result.Assessors)
		assert.Len(t, *result.Assessors, 1) // From first input
		assert.NotNil(t, result.Claims)
		assert.Len(t, *result.Claims, 1) // From second input

		// Complex fields - first input wins
		assert.NotNil(t, result.Targets.Organizations)
		assert.Nil(t, result.Targets.Components)
		assert.Equal(t, "Statement A", result.Affirmation.Statement)
	})
}