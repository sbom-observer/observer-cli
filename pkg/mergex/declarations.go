package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeDeclarations merges two cyclonedx.Declarations structs non-destructively.
// Since Declarations does not have a unique identifier like BOMRef, this function
// merges all fields directly. For complex fields, the first input takes precedence.
// For array fields, items from both inputs are combined.
// Returns a new Declarations struct without modifying the inputs.
func mergeDeclarations(a, b *cyclonedx.Declarations) *cyclonedx.Declarations {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		return copyDeclarations(b)
	}
	if b == nil {
		return copyDeclarations(a)
	}

	result := &cyclonedx.Declarations{}

	// Merge complex fields - first input takes precedence
	if a.Targets != nil {
		result.Targets = copyTargets(a.Targets)
	} else {
		result.Targets = copyTargets(b.Targets)
	}

	if a.Affirmation != nil {
		result.Affirmation = copyAffirmation(a.Affirmation)
	} else {
		result.Affirmation = copyAffirmation(b.Affirmation)
	}

	if a.Signature != nil {
		result.Signature = copyJSFSignature(a.Signature)
	} else {
		result.Signature = copyJSFSignature(b.Signature)
	}

	// Merge array fields by concatenation
	result.Assessors = mergeAssessorSlice(a.Assessors, b.Assessors)
	result.Attestations = mergeAttestationSlice(a.Attestations, b.Attestations)
	result.Claims = mergeClaimSlice(a.Claims, b.Claims)
	result.Evidence = mergeDeclarationEvidenceSlice(a.Evidence, b.Evidence)

	return result
}

// Helper copy functions

func copyDeclarations(declarations *cyclonedx.Declarations) *cyclonedx.Declarations {
	if declarations == nil {
		return nil
	}

	result := &cyclonedx.Declarations{
		Targets:     copyTargets(declarations.Targets),
		Affirmation: copyAffirmation(declarations.Affirmation),
		Signature:   copyJSFSignature(declarations.Signature),
	}

	result.Assessors = copyAssessorSlice(declarations.Assessors)
	result.Attestations = copyAttestationSlice(declarations.Attestations)
	result.Claims = copyClaimSlice(declarations.Claims)
	result.Evidence = copyDeclarationEvidenceSlice(declarations.Evidence)

	return result
}

func copyTargets(targets *cyclonedx.Targets) *cyclonedx.Targets {
	if targets == nil {
		return nil
	}

	result := &cyclonedx.Targets{}

	if targets.Organizations != nil {
		orgs := make([]cyclonedx.OrganizationalEntity, len(*targets.Organizations))
		copy(orgs, *targets.Organizations)
		result.Organizations = &orgs
	}

	if targets.Components != nil {
		comps := make([]cyclonedx.Component, len(*targets.Components))
		copy(comps, *targets.Components)
		result.Components = &comps
	}

	if targets.Services != nil {
		svcs := make([]cyclonedx.Service, len(*targets.Services))
		copy(svcs, *targets.Services)
		result.Services = &svcs
	}

	return result
}

func copyAffirmation(affirmation *cyclonedx.Affirmation) *cyclonedx.Affirmation {
	if affirmation == nil {
		return nil
	}

	result := &cyclonedx.Affirmation{
		Statement: affirmation.Statement,
		Signature: copyJSFSignature(affirmation.Signature),
	}

	if affirmation.Signatories != nil {
		sigs := make([]cyclonedx.Signatory, len(*affirmation.Signatories))
		copy(sigs, *affirmation.Signatories)
		result.Signatories = &sigs
	}

	return result
}

func copyJSFSignature(signature *cyclonedx.JSFSignature) *cyclonedx.JSFSignature {
	if signature == nil {
		return nil
	}
	// Simple shallow copy for now - deep copy would be needed for production
	copy := *signature
	return &copy
}

// Helper merge functions for array types

func mergeAssessorSlice(a, b *[]cyclonedx.Assessor) *[]cyclonedx.Assessor {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Assessor

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

func mergeAttestationSlice(a, b *[]cyclonedx.Attestation) *[]cyclonedx.Attestation {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Attestation

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

func mergeClaimSlice(a, b *[]cyclonedx.Claim) *[]cyclonedx.Claim {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Claim

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

func mergeDeclarationEvidenceSlice(a, b *[]cyclonedx.DeclarationEvidence) *[]cyclonedx.DeclarationEvidence {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.DeclarationEvidence

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

// Helper copy functions for array types

func copyAssessorSlice(assessors *[]cyclonedx.Assessor) *[]cyclonedx.Assessor {
	if assessors == nil {
		return nil
	}
	result := make([]cyclonedx.Assessor, len(*assessors))
	copy(result, *assessors)
	return &result
}

func copyAttestationSlice(attestations *[]cyclonedx.Attestation) *[]cyclonedx.Attestation {
	if attestations == nil {
		return nil
	}
	result := make([]cyclonedx.Attestation, len(*attestations))
	copy(result, *attestations)
	return &result
}

func copyClaimSlice(claims *[]cyclonedx.Claim) *[]cyclonedx.Claim {
	if claims == nil {
		return nil
	}
	result := make([]cyclonedx.Claim, len(*claims))
	copy(result, *claims)
	return &result
}

func copyDeclarationEvidenceSlice(evidence *[]cyclonedx.DeclarationEvidence) *[]cyclonedx.DeclarationEvidence {
	if evidence == nil {
		return nil
	}
	result := make([]cyclonedx.DeclarationEvidence, len(*evidence))
	copy(result, *evidence)
	return &result
}