package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// MergeComponent merges two cyclonedx.Component structs non-destructively.
// For non-array fields, the first input (a) takes precedence.
// For array fields, items from both inputs are combined.
// Returns a new Component struct without modifying the inputs.
func MergeComponent(a, b cyclonedx.Component) cyclonedx.Component {
	result := cyclonedx.Component{}

	// Simple string fields - first input wins
	result.BOMRef = firstNonEmpty(a.BOMRef, b.BOMRef)
	result.MIMEType = firstNonEmpty(a.MIMEType, b.MIMEType)
	result.Type = a.Type
	if result.Type == "" {
		result.Type = b.Type
	}
	result.Author = firstNonEmpty(a.Author, b.Author)
	result.Publisher = firstNonEmpty(a.Publisher, b.Publisher)
	result.Group = firstNonEmpty(a.Group, b.Group)
	result.Name = firstNonEmpty(a.Name, b.Name)
	result.Version = firstNonEmpty(a.Version, b.Version)
	result.Description = firstNonEmpty(a.Description, b.Description)
	result.Scope = a.Scope
	if result.Scope == "" {
		result.Scope = b.Scope
	}
	result.Copyright = firstNonEmpty(a.Copyright, b.Copyright)
	result.CPE = firstNonEmpty(a.CPE, b.CPE)
	result.PackageURL = firstNonEmpty(a.PackageURL, b.PackageURL)

	// Complex pointer fields - merge recursively with first input precedence
	result.Supplier = mergeOrganizationalEntity(a.Supplier, b.Supplier)
	result.Manufacturer = mergeOrganizationalEntity(a.Manufacturer, b.Manufacturer)
	result.SWID = mergeSWID(a.SWID, b.SWID)
	result.Pedigree = mergePedigree(a.Pedigree, b.Pedigree)
	result.Evidence = mergeEvidence(a.Evidence, b.Evidence)
	result.ReleaseNotes = mergeReleaseNotes(a.ReleaseNotes, b.ReleaseNotes)
	result.ModelCard = mergeMLModelCard(a.ModelCard, b.ModelCard)
	result.Data = mergeComponentData(a.Data, b.Data)
	result.CryptoProperties = mergeCryptoProperties(a.CryptoProperties, b.CryptoProperties)

	// Boolean pointer field
	result.Modified = a.Modified
	if result.Modified == nil {
		result.Modified = b.Modified
	}

	// Array fields - combine both inputs
	result.Authors = mergeOrganizationalContactSlice(a.Authors, b.Authors)
	result.OmniborID = mergeStringSlice(a.OmniborID, b.OmniborID)
	result.SWHID = mergeStringSlice(a.SWHID, b.SWHID)
	result.Hashes = mergeHashSlice(a.Hashes, b.Hashes)
	result.Licenses = mergeLicenses(a.Licenses, b.Licenses)
	result.ExternalReferences = mergeExternalReferenceSlice(a.ExternalReferences, b.ExternalReferences)
	result.Properties = mergePropertySlice(a.Properties, b.Properties)
	result.Components = mergeComponentSlice(a.Components, b.Components)

	return result
}

// firstNonEmpty returns the first non-empty string
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// mergeOrganizationalEntity merges two OrganizationalEntity pointers
func mergeOrganizationalEntity(a, b *cyclonedx.OrganizationalEntity) *cyclonedx.OrganizationalEntity {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		result := *b
		if b.Address != nil {
			addr := *b.Address
			result.Address = &addr
		}
		if b.URL != nil {
			urls := make([]string, len(*b.URL))
			copy(urls, *b.URL)
			result.URL = &urls
		}
		if b.Contact != nil {
			contacts := make([]cyclonedx.OrganizationalContact, len(*b.Contact))
			copy(contacts, *b.Contact)
			result.Contact = &contacts
		}
		return &result
	}

	// Deep copy a as base
	result := *a
	if a.Address != nil {
		addr := *a.Address
		result.Address = &addr
	}
	if a.URL != nil {
		urls := make([]string, len(*a.URL))
		copy(urls, *a.URL)
		result.URL = &urls
	}
	if a.Contact != nil {
		contacts := make([]cyclonedx.OrganizationalContact, len(*a.Contact))
		copy(contacts, *a.Contact)
		result.Contact = &contacts
	}

	// Merge fields from b where a is empty
	if result.BOMRef == "" && b != nil {
		result.BOMRef = b.BOMRef
	}
	if result.Name == "" && b != nil {
		result.Name = b.Name
	}
	if result.Address == nil && b != nil && b.Address != nil {
		addr := *b.Address
		result.Address = &addr
	}

	// Merge array fields
	if b != nil {
		result.URL = mergeStringSlice(result.URL, b.URL)
		result.Contact = mergeOrganizationalContactSlice(result.Contact, b.Contact)
	}

	return &result
}

// mergeSWID merges two SWID pointers
func mergeSWID(a, b *cyclonedx.SWID) *cyclonedx.SWID {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		result := *b
		if b.Text != nil {
			text := *b.Text
			result.Text = &text
		}
		return &result
	}

	// Deep copy a as base
	result := *a
	if a.Text != nil {
		text := *a.Text
		result.Text = &text
	}

	// Fill empty fields from b
	if result.URL == "" && b != nil {
		result.URL = b.URL
	}
	if result.TagID == "" && b != nil {
		result.TagID = b.TagID
	}
	if result.Name == "" && b != nil {
		result.Name = b.Name
	}
	if result.Version == "" && b != nil {
		result.Version = b.Version
	}
	if result.Text == nil && b != nil && b.Text != nil {
		text := *b.Text
		result.Text = &text
	}

	return &result
}

// mergePedigree merges two Pedigree pointers
func mergePedigree(a, b *cyclonedx.Pedigree) *cyclonedx.Pedigree {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		result := cyclonedx.Pedigree{}
		if b.Ancestors != nil {
			ancestors := make([]cyclonedx.Component, len(*b.Ancestors))
			copy(ancestors, *b.Ancestors)
			result.Ancestors = &ancestors
		}
		if b.Descendants != nil {
			descendants := make([]cyclonedx.Component, len(*b.Descendants))
			copy(descendants, *b.Descendants)
			result.Descendants = &descendants
		}
		if b.Variants != nil {
			variants := make([]cyclonedx.Component, len(*b.Variants))
			copy(variants, *b.Variants)
			result.Variants = &variants
		}
		if b.Commits != nil {
			commits := make([]cyclonedx.Commit, len(*b.Commits))
			copy(commits, *b.Commits)
			result.Commits = &commits
		}
		if b.Patches != nil {
			patches := make([]cyclonedx.Patch, len(*b.Patches))
			copy(patches, *b.Patches)
			result.Patches = &patches
		}
		return &result
	}

	// Start with deep copy of a
	result := cyclonedx.Pedigree{}
	if a.Ancestors != nil {
		ancestors := make([]cyclonedx.Component, len(*a.Ancestors))
		copy(ancestors, *a.Ancestors)
		result.Ancestors = &ancestors
	}
	if a.Descendants != nil {
		descendants := make([]cyclonedx.Component, len(*a.Descendants))
		copy(descendants, *a.Descendants)
		result.Descendants = &descendants
	}
	if a.Variants != nil {
		variants := make([]cyclonedx.Component, len(*a.Variants))
		copy(variants, *a.Variants)
		result.Variants = &variants
	}
	if a.Commits != nil {
		commits := make([]cyclonedx.Commit, len(*a.Commits))
		copy(commits, *a.Commits)
		result.Commits = &commits
	}
	if a.Patches != nil {
		patches := make([]cyclonedx.Patch, len(*a.Patches))
		copy(patches, *a.Patches)
		result.Patches = &patches
	}

	// Merge arrays from b
	if b != nil {
		result.Ancestors = mergeComponentSlice(result.Ancestors, b.Ancestors)
		result.Descendants = mergeComponentSlice(result.Descendants, b.Descendants)
		result.Variants = mergeComponentSlice(result.Variants, b.Variants)
		result.Commits = mergeCommitSlice(result.Commits, b.Commits)
		result.Patches = mergePatchSlice(result.Patches, b.Patches)
	}

	return &result
}

// mergeEvidence merges two Evidence pointers
func mergeEvidence(a, b *cyclonedx.Evidence) *cyclonedx.Evidence {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		result := cyclonedx.Evidence{}
		if b.Identity != nil {
			identity := make([]cyclonedx.EvidenceIdentity, len(*b.Identity))
			copy(identity, *b.Identity)
			result.Identity = &identity
		}
		if b.Occurrences != nil {
			occurrences := make([]cyclonedx.EvidenceOccurrence, len(*b.Occurrences))
			copy(occurrences, *b.Occurrences)
			result.Occurrences = &occurrences
		}
		if b.Callstack != nil {
			callstack := *b.Callstack
			result.Callstack = &callstack
		}
		if b.Licenses != nil {
			licenses := *b.Licenses
			result.Licenses = &licenses
		}
		if b.Copyright != nil {
			copyright := make([]cyclonedx.Copyright, len(*b.Copyright))
			copy(copyright, *b.Copyright)
			result.Copyright = &copyright
		}
		return &result
	}

	// Start with deep copy of a
	result := cyclonedx.Evidence{}
	if a.Identity != nil {
		identity := make([]cyclonedx.EvidenceIdentity, len(*a.Identity))
		copy(identity, *a.Identity)
		result.Identity = &identity
	}
	if a.Occurrences != nil {
		occurrences := make([]cyclonedx.EvidenceOccurrence, len(*a.Occurrences))
		copy(occurrences, *a.Occurrences)
		result.Occurrences = &occurrences
	}
	if a.Callstack != nil {
		callstack := *a.Callstack
		result.Callstack = &callstack
	}
	if a.Licenses != nil {
		licenses := *a.Licenses
		result.Licenses = &licenses
	}
	if a.Copyright != nil {
		copyright := make([]cyclonedx.Copyright, len(*a.Copyright))
		copy(copyright, *a.Copyright)
		result.Copyright = &copyright
	}

	// Merge arrays from b
	if b != nil {
		result.Identity = mergeEvidenceIdentitySlice(result.Identity, b.Identity)
		result.Occurrences = mergeEvidenceOccurrenceSlice(result.Occurrences, b.Occurrences)
		result.Copyright = mergeCopyrightSlice(result.Copyright, b.Copyright)

		// For non-arrays, use first input precedence but fill if empty
		if result.Callstack == nil {
			result.Callstack = b.Callstack
		}
		if result.Licenses == nil {
			result.Licenses = b.Licenses
		} else if b.Licenses != nil {
			// Merge licenses
			merged := mergeLicenses(result.Licenses, b.Licenses)
			result.Licenses = merged
		}
	}

	return &result
}

// Placeholder implementations for complex type mergers - these need to be implemented
func mergeReleaseNotes(a, b *cyclonedx.ReleaseNotes) *cyclonedx.ReleaseNotes {
	if a == nil {
		return b
	}
	return a
}

func mergeMLModelCard(a, b *cyclonedx.MLModelCard) *cyclonedx.MLModelCard {
	if a == nil {
		return b
	}
	return a
}

func mergeComponentData(a, b *cyclonedx.ComponentData) *cyclonedx.ComponentData {
	if a == nil {
		return b
	}
	return a
}

func mergeCryptoProperties(a, b *cyclonedx.CryptoProperties) *cyclonedx.CryptoProperties {
	if a == nil {
		return b
	}
	return a
}

// mergeLicenses merges two Licenses pointers
func mergeLicenses(a, b *cyclonedx.Licenses) *cyclonedx.Licenses {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		result := make(cyclonedx.Licenses, len(*b))
		copy(result, *b)
		return &result
	}

	if b == nil {
		// Deep copy a
		result := make(cyclonedx.Licenses, len(*a))
		copy(result, *a)
		return &result
	}

	// Combine both licenses
	result := make(cyclonedx.Licenses, 0, len(*a)+len(*b))
	result = append(result, *a...)
	result = append(result, *b...)
	return &result
}

// Array merge helper functions
func mergeStringSlice(a, b *[]string) *[]string {
	if a == nil && b == nil {
		return nil
	}

	var result []string
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

func mergeOrganizationalContactSlice(a, b *[]cyclonedx.OrganizationalContact) *[]cyclonedx.OrganizationalContact {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.OrganizationalContact
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

func mergeHashSlice(a, b *[]cyclonedx.Hash) *[]cyclonedx.Hash {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Hash
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

func mergeExternalReferenceSlice(a, b *[]cyclonedx.ExternalReference) *[]cyclonedx.ExternalReference {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.ExternalReference
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

func mergePropertySlice(a, b *[]cyclonedx.Property) *[]cyclonedx.Property {
	if a == nil && b == nil {
		return nil
	}

	// Use map to merge by key - first input wins for duplicate keys
	propMap := make(map[string]cyclonedx.Property)

	// First add all properties from b
	if b != nil {
		for _, prop := range *b {
			propMap[prop.Name] = prop
		}
	}

	// Then add all properties from a (overwriting any duplicates from b)
	if a != nil {
		for _, prop := range *a {
			propMap[prop.Name] = prop
		}
	}

	if len(propMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Property, 0, len(propMap))
	for _, prop := range propMap {
		result = append(result, prop)
	}

	return &result
}

func mergeComponentSlice(a, b *[]cyclonedx.Component) *[]cyclonedx.Component {
	if a == nil && b == nil {
		return nil
	}

	// Use map to track components by BOMRef for deduplication
	componentMap := make(map[string]cyclonedx.Component)

	// First add all components from a
	if a != nil {
		for _, comp := range *a {
			if comp.BOMRef != "" {
				componentMap[comp.BOMRef] = comp
			} else {
				// Components without BOMRef are always included
				// Use a temporary key based on name+version+packageURL for deduplication
				key := comp.Name + "|" + comp.Version + "|" + comp.PackageURL
				if _, exists := componentMap[key]; !exists {
					componentMap[key] = comp
				}
			}
		}
	}

	// Then process components from b
	if b != nil {
		for _, comp := range *b {
			if comp.BOMRef != "" {
				if existing, exists := componentMap[comp.BOMRef]; exists {
					// Merge components with same BOMRef
					componentMap[comp.BOMRef] = MergeComponent(existing, comp)
				} else {
					// Add new component with unique BOMRef
					componentMap[comp.BOMRef] = comp
				}
			} else {
				// Components without BOMRef are always included if not duplicate
				key := comp.Name + "|" + comp.Version + "|" + comp.PackageURL
				if existing, exists := componentMap[key]; exists {
					// Merge components with same key
					componentMap[key] = MergeComponent(existing, comp)
				} else {
					componentMap[key] = comp
				}
			}
		}
	}

	if len(componentMap) == 0 {
		return nil
	}

	// Convert back to slice
	result := make([]cyclonedx.Component, 0, len(componentMap))
	for _, comp := range componentMap {
		result = append(result, comp)
	}

	return &result
}

// Placeholder slice merge functions - need proper implementations
func mergeCommitSlice(a, b *[]cyclonedx.Commit) *[]cyclonedx.Commit {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Commit
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

func mergePatchSlice(a, b *[]cyclonedx.Patch) *[]cyclonedx.Patch {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Patch
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

func mergeEvidenceIdentitySlice(a, b *[]cyclonedx.EvidenceIdentity) *[]cyclonedx.EvidenceIdentity {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.EvidenceIdentity
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

func mergeEvidenceOccurrenceSlice(a, b *[]cyclonedx.EvidenceOccurrence) *[]cyclonedx.EvidenceOccurrence {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.EvidenceOccurrence
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

func mergeCopyrightSlice(a, b *[]cyclonedx.Copyright) *[]cyclonedx.Copyright {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Copyright
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
