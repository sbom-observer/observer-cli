package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeService merges two cyclonedx.Service structs non-destructively.
// Since BOMRef is a unique identifier, this function assumes both services have the same BOMRef.
// For non-array fields, the first input takes precedence.
// For array fields, items from both inputs are combined.
// Returns a new Service struct without modifying the inputs.
func mergeService(a, b cyclonedx.Service) cyclonedx.Service {
	result := cyclonedx.Service{
		BOMRef: a.BOMRef, // Both should have the same BOMRef, use first input
		Name:   a.Name,   // First input wins
	}

	// Fill empty simple fields from b where a is empty
	if a.Group == "" {
		result.Group = b.Group
	} else {
		result.Group = a.Group
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

	// Boolean pointers - first input wins if set, otherwise use second
	if a.Authenticated != nil {
		result.Authenticated = copyBoolPtr(a.Authenticated)
	} else {
		result.Authenticated = copyBoolPtr(b.Authenticated)
	}
	if a.CrossesTrustBoundary != nil {
		result.CrossesTrustBoundary = copyBoolPtr(a.CrossesTrustBoundary)
	} else {
		result.CrossesTrustBoundary = copyBoolPtr(b.CrossesTrustBoundary)
	}

	// Merge complex fields
	if a.Provider == nil {
		result.Provider = copyOrganizationalEntity(b.Provider)
	} else if b.Provider != nil {
		result.Provider = mergeOrganizationalEntity(a.Provider, b.Provider)
	} else {
		result.Provider = copyOrganizationalEntity(a.Provider)
	}

	if a.Licenses == nil {
		result.Licenses = copyLicenses(b.Licenses)
	} else if b.Licenses != nil {
		result.Licenses = mergeLicenses(a.Licenses, b.Licenses)
	} else {
		result.Licenses = copyLicenses(a.Licenses)
	}

	if a.ReleaseNotes == nil {
		if b.ReleaseNotes != nil {
			copy := *b.ReleaseNotes
			result.ReleaseNotes = &copy
		}
	} else if b.ReleaseNotes != nil {
		result.ReleaseNotes = mergeReleaseNotes(a.ReleaseNotes, b.ReleaseNotes)
	} else {
		copy := *a.ReleaseNotes
		result.ReleaseNotes = &copy
	}

	// Merge array fields
	result.Endpoints = mergeStringSliceWithDeduplication(a.Endpoints, b.Endpoints)
	result.Data = mergeDataClassificationSlice(a.Data, b.Data)
	result.ExternalReferences = mergeExternalReferenceSlice(a.ExternalReferences, b.ExternalReferences)
	result.Properties = mergePropertySlice(a.Properties, b.Properties)
	result.Services = mergeServiceSliceInternal(a.Services, b.Services) // Recursive merge

	return result
}

// mergeServiceSliceInternal merges two Service slices non-destructively.
// Services with the same BOMRef are merged together.
// Services with unique BOMRefs are included as-is.
// Returns a new slice without modifying the inputs.
func mergeServiceSliceInternal(a, b *[]cyclonedx.Service) *[]cyclonedx.Service {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track services by BOMRef
	serviceMap := make(map[string]cyclonedx.Service)

	// First add all services from a
	if a != nil {
		for _, svc := range *a {
			serviceMap[svc.BOMRef] = svc
		}
	}

	// Then process services from b
	if b != nil {
		for _, svc := range *b {
			if existing, exists := serviceMap[svc.BOMRef]; exists {
				// Merge with existing service (same BOMRef)
				serviceMap[svc.BOMRef] = mergeService(existing, svc)
			} else {
				// Add new service (unique BOMRef)
				serviceMap[svc.BOMRef] = svc
			}
		}
	}

	if len(serviceMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Service, 0, len(serviceMap))
	for _, svc := range serviceMap {
		result = append(result, svc)
	}

	return &result
}

// Helper copy and merge functions for complex types

func copyBoolPtr(b *bool) *bool {
	if b == nil {
		return nil
	}
	copy := *b
	return &copy
}

// Note: copyOrganizationalEntity, mergeOrganizationalEntity, copyLicenses, 
// mergeLicenses, copyReleaseNotes, and mergeReleaseNotes are already 
// defined in other files in this package

func mergeDataClassificationSlice(a, b *[]cyclonedx.DataClassification) *[]cyclonedx.DataClassification {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.DataClassification

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