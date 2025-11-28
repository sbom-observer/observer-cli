package mergex

import (
	"github.com/CycloneDX/cyclonedx-go"
)

// mergeMetadata merges two cyclonedx.Metadata structs non-destructively.
// For non-array fields, the first input (a) takes precedence.
// For array fields, items from both inputs are combined.
// Returns a new Metadata struct without modifying the inputs.
func mergeMetadata(a, b *cyclonedx.Metadata) *cyclonedx.Metadata {
	if a == nil {
		if b == nil {
			return nil
		}
		// Deep copy b
		return copyMetadata(b)
	}

	if b == nil {
		// Deep copy a
		return copyMetadata(a)
	}

	// Start with deep copy of a as base
	result := copyMetadata(a)

	// Fill empty fields from b where a is empty
	if result.Timestamp == "" {
		result.Timestamp = b.Timestamp
	}

	// Merge complex pointer fields
	if result.Tools == nil {
		result.Tools = copyToolsChoice(b.Tools)
	} else if b.Tools != nil {
		result.Tools = mergeToolsChoice(result.Tools, b.Tools)
	}

	if result.Component == nil {
		result.Component = copyComponent(b.Component)
	} else if b.Component != nil {
		merged := MergeComponent(*result.Component, *b.Component)
		result.Component = &merged
	}

	if result.Manufacture == nil {
		result.Manufacture = copyOrganizationalEntity(b.Manufacture)
	} else if b.Manufacture != nil {
		result.Manufacture = mergeOrganizationalEntity(result.Manufacture, b.Manufacture)
	}

	if result.Manufacturer == nil {
		result.Manufacturer = copyOrganizationalEntity(b.Manufacturer)
	} else if b.Manufacturer != nil {
		result.Manufacturer = mergeOrganizationalEntity(result.Manufacturer, b.Manufacturer)
	}

	if result.Supplier == nil {
		result.Supplier = copyOrganizationalEntity(b.Supplier)
	} else if b.Supplier != nil {
		result.Supplier = mergeOrganizationalEntity(result.Supplier, b.Supplier)
	}

	// Merge array fields
	result.Lifecycles = mergeLifecycleSlice(result.Lifecycles, b.Lifecycles)
	result.Authors = mergeOrganizationalContactSlice(result.Authors, b.Authors)
	result.Licenses = mergeLicenses(result.Licenses, b.Licenses)
	result.Properties = mergePropertySlice(result.Properties, b.Properties)

	return result
}

// copyMetadata creates a deep copy of a Metadata struct
func copyMetadata(m *cyclonedx.Metadata) *cyclonedx.Metadata {
	if m == nil {
		return nil
	}

	result := &cyclonedx.Metadata{
		Timestamp: m.Timestamp,
	}

	result.Lifecycles = copyLifecycleSlice(m.Lifecycles)
	result.Tools = copyToolsChoice(m.Tools)
	result.Authors = copyOrganizationalContactSlice(m.Authors)
	result.Component = copyComponent(m.Component)
	result.Manufacture = copyOrganizationalEntity(m.Manufacture)
	result.Manufacturer = copyOrganizationalEntity(m.Manufacturer)
	result.Supplier = copyOrganizationalEntity(m.Supplier)
	result.Licenses = copyLicenses(m.Licenses)
	result.Properties = copyPropertySlice(m.Properties)

	return result
}

// mergeToolsChoice merges two ToolsChoice structs
func mergeToolsChoice(a, b *cyclonedx.ToolsChoice) *cyclonedx.ToolsChoice {
	if a == nil {
		return copyToolsChoice(b)
	}
	if b == nil {
		return copyToolsChoice(a)
	}

	result := &cyclonedx.ToolsChoice{}

	// Merge arrays - combine both inputs
	result.Tools = mergeToolSlice(a.Tools, b.Tools)
	result.Components = mergeComponentSlice(a.Components, b.Components)
	result.Services = mergeServiceSlice(a.Services, b.Services)

	return result
}

// mergeLifecycleSlice merges two Lifecycle slices
func mergeLifecycleSlice(a, b *[]cyclonedx.Lifecycle) *[]cyclonedx.Lifecycle {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Lifecycle
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

// mergeToolSlice merges two Tool slices
func mergeToolSlice(a, b *[]cyclonedx.Tool) *[]cyclonedx.Tool {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Tool
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

// mergeServiceSlice merges two Service slices
func mergeServiceSlice(a, b *[]cyclonedx.Service) *[]cyclonedx.Service {
	if a == nil && b == nil {
		return nil
	}

	var result []cyclonedx.Service
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

// Copy helper functions
func copyToolsChoice(tc *cyclonedx.ToolsChoice) *cyclonedx.ToolsChoice {
	if tc == nil {
		return nil
	}

	result := &cyclonedx.ToolsChoice{}
	result.Tools = copyToolSlice(tc.Tools)
	result.Components = copyComponentSlice(tc.Components)
	result.Services = copyServiceSlice(tc.Services)

	return result
}

func copyComponent(c *cyclonedx.Component) *cyclonedx.Component {
	if c == nil {
		return nil
	}
	// Use existing MergeComponent with empty second param to get a deep copy
	copied := MergeComponent(*c, cyclonedx.Component{})
	return &copied
}

func copyOrganizationalEntity(oe *cyclonedx.OrganizationalEntity) *cyclonedx.OrganizationalEntity {
	if oe == nil {
		return nil
	}
	// Use existing merge function with nil second param
	return mergeOrganizationalEntity(oe, nil)
}

func copyLicenses(l *cyclonedx.Licenses) *cyclonedx.Licenses {
	if l == nil {
		return nil
	}
	result := make(cyclonedx.Licenses, len(*l))
	copy(result, *l)
	return &result
}

func copyPropertySlice(p *[]cyclonedx.Property) *[]cyclonedx.Property {
	if p == nil {
		return nil
	}
	result := make([]cyclonedx.Property, len(*p))
	copy(result, *p)
	return &result
}

func copyLifecycleSlice(l *[]cyclonedx.Lifecycle) *[]cyclonedx.Lifecycle {
	if l == nil {
		return nil
	}
	result := make([]cyclonedx.Lifecycle, len(*l))
	copy(result, *l)
	return &result
}

func copyOrganizationalContactSlice(oc *[]cyclonedx.OrganizationalContact) *[]cyclonedx.OrganizationalContact {
	if oc == nil {
		return nil
	}
	result := make([]cyclonedx.OrganizationalContact, len(*oc))
	copy(result, *oc)
	return &result
}

func copyToolSlice(t *[]cyclonedx.Tool) *[]cyclonedx.Tool {
	if t == nil {
		return nil
	}
	result := make([]cyclonedx.Tool, len(*t))
	copy(result, *t)
	return &result
}

func copyComponentSlice(c *[]cyclonedx.Component) *[]cyclonedx.Component {
	if c == nil {
		return nil
	}
	result := make([]cyclonedx.Component, len(*c))
	copy(result, *c)
	return &result
}

func copyServiceSlice(s *[]cyclonedx.Service) *[]cyclonedx.Service {
	if s == nil {
		return nil
	}
	result := make([]cyclonedx.Service, len(*s))
	copy(result, *s)
	return &result
}
