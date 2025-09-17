package mergex

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeBOM_Nil(t *testing.T) {
	tests := []struct {
		name     string
		a        *cyclonedx.BOM
		b        *cyclonedx.BOM
		expected *cyclonedx.BOM
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name: "first nil, second has value",
			a:    nil,
			b: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-b",
				Version:      1,
			},
			expected: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-b",
				Version:      1,
			},
		},
		{
			name: "first has value, second nil",
			a: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-a",
				Version:      1,
			},
			b: nil,
			expected: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-a",
				Version:      1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeBom(tt.a, tt.b)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected.SerialNumber, result.SerialNumber)
				assert.Equal(t, tt.expected.Version, result.Version)
			}
		})
	}
}

func TestMergeBOM_SimpleFields(t *testing.T) {
	t.Run("first input wins for non-empty fields", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Version:      1,
			BOMFormat:    "CycloneDX",
			SpecVersion:  cyclonedx.SpecVersion1_6,
			JSONSchema:   "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json",
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Version:      2,
			BOMFormat:    "Other",
			SpecVersion:  cyclonedx.SpecVersion1_5,
			JSONSchema:   "https://different-schema.json",
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.Equal(t, 1, result.Version)
		assert.Equal(t, "CycloneDX", result.BOMFormat)
		assert.Equal(t, cyclonedx.SpecVersion1_6, result.SpecVersion)
		assert.Equal(t, "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json", result.JSONSchema)
	})

	t.Run("second input fills empty fields", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			// Other fields empty
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Version:      2,
			BOMFormat:    "CycloneDX",
			SpecVersion:  cyclonedx.SpecVersion1_6,
			JSONSchema:   "https://schema.json",
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber) // First wins
		assert.Equal(t, 2, result.Version)                          // Second fills empty
		assert.Equal(t, "CycloneDX", result.BOMFormat)              // Second fills empty
		assert.Equal(t, cyclonedx.SpecVersion1_6, result.SpecVersion)
		assert.Equal(t, "https://schema.json", result.JSONSchema)
	})

	t.Run("version zero handling", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Version:      0, // Zero value
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Version:      5,
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.Equal(t, 5, result.Version) // Second input fills zero value
	})
}

func TestMergeBOM_Metadata(t *testing.T) {
	t.Run("merge metadata", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Timestamp: "2023-01-01T00:00:00Z",
				Authors: &[]cyclonedx.OrganizationalContact{
					{Name: "Author A"},
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Timestamp: "2023-02-01T00:00:00Z",
				Authors: &[]cyclonedx.OrganizationalContact{
					{Name: "Author B"},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Metadata)
		assert.Equal(t, "2023-01-01T00:00:00Z", result.Metadata.Timestamp) // First input wins
		assert.Len(t, *result.Metadata.Authors, 2)                         // Arrays merged
		assert.Equal(t, "Author A", (*result.Metadata.Authors)[0].Name)
		assert.Equal(t, "Author B", (*result.Metadata.Authors)[1].Name)
	})

	t.Run("fill nil metadata from second input", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata:     nil,
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Timestamp: "2023-02-01T00:00:00Z",
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Metadata)
		assert.Equal(t, "2023-02-01T00:00:00Z", result.Metadata.Timestamp)
	})
}

func TestMergeBOM_Components(t *testing.T) {
	t.Run("merge components", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Components: &[]cyclonedx.Component{
				{Name: "Component A", Version: "1.0.0"},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Components: &[]cyclonedx.Component{
				{Name: "Component B", Version: "2.0.0"},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 2)
		assert.Equal(t, "Component A", (*result.Components)[0].Name)
		assert.Equal(t, "Component B", (*result.Components)[1].Name)
	})
}

func TestMergeBOM_Dependencies(t *testing.T) {
	t.Run("merge dependencies with ref-based deduplication", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "component-a",
					Dependencies: &[]string{"dep1", "dep2"},
				},
				{
					Ref:          "component-b",
					Dependencies: &[]string{"dep3"},
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "component-a",             // Same ref as first BOM
					Dependencies: &[]string{"dep2", "dep4"}, // dep2 is duplicate
				},
				{
					Ref:          "component-c",
					Dependencies: &[]string{"dep5"},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 3) // component-a merged, b and c separate

		// Convert to map for easier testing since order is not guaranteed
		depMap := make(map[string]int)
		for _, dep := range *result.Dependencies {
			if dep.Dependencies != nil {
				depMap[dep.Ref] = len(*dep.Dependencies)
			}
		}

		// component-a should have merged dependencies (dep1, dep2, dep4 = 3 unique)
		assert.Equal(t, 3, depMap["component-a"])
		assert.Equal(t, 1, depMap["component-b"])
		assert.Equal(t, 1, depMap["component-c"])
	})
}

func TestMergeBOM_Properties(t *testing.T) {
	t.Run("merge properties by key", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "production"},
				{Name: "version", Value: "1.0.0"},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "staging"}, // duplicate key - first should win
				{Name: "owner", Value: "team-b"},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Properties)
		assert.Len(t, *result.Properties, 3) // 3 unique keys

		// Convert to map for easier testing since order is not guaranteed
		propMap := make(map[string]string)
		for _, prop := range *result.Properties {
			propMap[prop.Name] = prop.Value
		}

		assert.Equal(t, "production", propMap["env"]) // First input wins
		assert.Equal(t, "1.0.0", propMap["version"])
		assert.Equal(t, "team-b", propMap["owner"])
	})
}

func TestMergeBOM_ExternalReferences(t *testing.T) {
	t.Run("merge external references", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			ExternalReferences: &[]cyclonedx.ExternalReference{
				{URL: "https://example.com/a", Type: "website"},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			ExternalReferences: &[]cyclonedx.ExternalReference{
				{URL: "https://example.com/b", Type: "vcs"},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.ExternalReferences)
		assert.Len(t, *result.ExternalReferences, 2)
		assert.Equal(t, "https://example.com/a", (*result.ExternalReferences)[0].URL)
		assert.Equal(t, "https://example.com/b", (*result.ExternalReferences)[1].URL)
	})
}

func TestMergeBOM_Immutability(t *testing.T) {
	t.Run("original BOMs are not modified", func(t *testing.T) {
		originalA := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Version:      1,
			Components: &[]cyclonedx.Component{
				{Name: "Component A"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "env", Value: "production"},
			},
		}
		originalB := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Version:      2,
			Components: &[]cyclonedx.Component{
				{Name: "Component B"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "owner", Value: "team-b"},
			},
		}

		// Create copies for comparison
		copyA := &cyclonedx.BOM{
			SerialNumber: originalA.SerialNumber,
			Version:      originalA.Version,
			Components: &[]cyclonedx.Component{
				{Name: (*originalA.Components)[0].Name},
			},
			Properties: &[]cyclonedx.Property{
				{Name: (*originalA.Properties)[0].Name, Value: (*originalA.Properties)[0].Value},
			},
		}
		copyB := &cyclonedx.BOM{
			SerialNumber: originalB.SerialNumber,
			Version:      originalB.Version,
			Components: &[]cyclonedx.Component{
				{Name: (*originalB.Components)[0].Name},
			},
			Properties: &[]cyclonedx.Property{
				{Name: (*originalB.Properties)[0].Name, Value: (*originalB.Properties)[0].Value},
			},
		}

		result := MergeBom(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, copyA.SerialNumber, originalA.SerialNumber)
		assert.Equal(t, copyA.Version, originalA.Version)
		assert.Equal(t, (*copyA.Components)[0].Name, (*originalA.Components)[0].Name)
		assert.Equal(t, (*copyA.Properties)[0].Name, (*originalA.Properties)[0].Name)

		assert.Equal(t, copyB.SerialNumber, originalB.SerialNumber)
		assert.Equal(t, copyB.Version, originalB.Version)
		assert.Equal(t, (*copyB.Components)[0].Name, (*originalB.Components)[0].Name)
		assert.Equal(t, (*copyB.Properties)[0].Name, (*originalB.Properties)[0].Name)

		// Verify result is merged correctly
		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber) // First input wins
		assert.Equal(t, 1, result.Version)                          // First input wins
		assert.Len(t, *result.Components, 2)                        // Combined
		assert.Len(t, *result.Properties, 2)                        // Combined
	})
}

func TestMergeBOM_Services(t *testing.T) {
	t.Run("merge services with BOMRef-based deduplication", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Services: &[]cyclonedx.Service{
				{
					BOMRef:      "service-1",
					Name:        "Service A",
					Version:     "1.0.0",
					Description: "Service A description",
				},
				{
					BOMRef: "service-2",
					Name:   "Service B",
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Services: &[]cyclonedx.Service{
				{
					BOMRef:      "service-1", // Same BOMRef - should merge
					Name:        "Service A Updated",
					Description: "Different description", // First input should win
				},
				{
					BOMRef: "service-3",
					Name:   "Service C",
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Services)
		assert.Len(t, *result.Services, 3) // service-1 merged, service-2 and service-3 separate

		// Convert to map for easier testing since order is not guaranteed
		serviceMap := make(map[string]cyclonedx.Service)
		for _, service := range *result.Services {
			serviceMap[service.BOMRef] = service
		}

		// service-1 should have merged with first input winning for non-empty fields
		assert.Equal(t, "Service A", serviceMap["service-1"].Name)                    // First input wins
		assert.Equal(t, "1.0.0", serviceMap["service-1"].Version)                     // First input wins
		assert.Equal(t, "Service A description", serviceMap["service-1"].Description) // First input wins

		assert.Equal(t, "Service B", serviceMap["service-2"].Name)
		assert.Equal(t, "Service C", serviceMap["service-3"].Name)
	})
}

func TestMergeBOM_Compositions(t *testing.T) {
	t.Run("merge compositions with BOMRef-based deduplication", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Compositions: &[]cyclonedx.Composition{
				{
					BOMRef:     "composition-1",
					Aggregate:  cyclonedx.CompositionAggregateComplete,
					Assemblies: &[]cyclonedx.BOMReference{"assembly-1", "assembly-2"},
				},
				{
					BOMRef:    "composition-2",
					Aggregate: cyclonedx.CompositionAggregateIncomplete,
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Compositions: &[]cyclonedx.Composition{
				{
					BOMRef:     "composition-1", // Same BOMRef - should merge
					Aggregate:  cyclonedx.CompositionAggregateIncompleteFirstPartyOnly,
					Assemblies: &[]cyclonedx.BOMReference{"assembly-2", "assembly-3"}, // assembly-2 is duplicate
				},
				{
					BOMRef:    "composition-3",
					Aggregate: cyclonedx.CompositionAggregateUnknown,
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Compositions)
		assert.Len(t, *result.Compositions, 3) // composition-1 merged, composition-2 and composition-3 separate

		// Convert to map for easier testing since order is not guaranteed
		compositionMap := make(map[string]cyclonedx.Composition)
		for _, composition := range *result.Compositions {
			compositionMap[composition.BOMRef] = composition
		}

		// composition-1 should have merged with first input winning
		assert.Equal(t, cyclonedx.CompositionAggregateComplete, compositionMap["composition-1"].Aggregate) // First input wins
		assert.NotNil(t, compositionMap["composition-1"].Assemblies)
		assert.Len(t, *compositionMap["composition-1"].Assemblies, 3) // Unique assemblies: assembly-1, assembly-2, assembly-3

		assert.Equal(t, cyclonedx.CompositionAggregateIncomplete, compositionMap["composition-2"].Aggregate)
		assert.Equal(t, cyclonedx.CompositionAggregateUnknown, compositionMap["composition-3"].Aggregate)
	})
}

func TestMergeBOM_Vulnerabilities(t *testing.T) {
	t.Run("merge vulnerabilities with BOMRef-based deduplication", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Vulnerabilities: &[]cyclonedx.Vulnerability{
				{
					BOMRef:      "vuln-1",
					ID:          "CVE-2023-1234",
					Description: "Critical vulnerability",
					Detail:      "Detailed description A",
				},
				{
					BOMRef: "vuln-2",
					ID:     "CVE-2023-5678",
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Vulnerabilities: &[]cyclonedx.Vulnerability{
				{
					BOMRef:      "vuln-1", // Same BOMRef - should merge
					ID:          "CVE-2023-1234-updated",
					Description: "Updated description", // First input should win
					Detail:      "Detailed description B",
				},
				{
					BOMRef: "vuln-3",
					ID:     "CVE-2023-9999",
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Vulnerabilities)
		assert.Len(t, *result.Vulnerabilities, 3) // vuln-1 merged, vuln-2 and vuln-3 separate

		// Convert to map for easier testing since order is not guaranteed
		vulnMap := make(map[string]cyclonedx.Vulnerability)
		for _, vuln := range *result.Vulnerabilities {
			vulnMap[vuln.BOMRef] = vuln
		}

		// vuln-1 should have merged with first input winning for non-empty fields
		assert.Equal(t, "CVE-2023-1234", vulnMap["vuln-1"].ID)                   // First input wins
		assert.Equal(t, "Critical vulnerability", vulnMap["vuln-1"].Description) // First input wins
		assert.Equal(t, "Detailed description A", vulnMap["vuln-1"].Detail)      // First input wins

		assert.Equal(t, "CVE-2023-5678", vulnMap["vuln-2"].ID)
		assert.Equal(t, "CVE-2023-9999", vulnMap["vuln-3"].ID)
	})
}

func TestMergeBOM_Annotations(t *testing.T) {
	t.Run("merge annotations with BOMRef-based deduplication", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Annotations: &[]cyclonedx.Annotation{
				{
					BOMRef:   "annotation-1",
					Subjects: &[]cyclonedx.BOMReference{"component-a"},
					Annotator: &cyclonedx.Annotator{
						Organization: &cyclonedx.OrganizationalEntity{Name: "Annotator A"},
					},
					Timestamp: "2023-01-01T00:00:00Z",
					Text:      "Annotation A text",
				},
				{
					BOMRef:   "annotation-2",
					Subjects: &[]cyclonedx.BOMReference{"component-b"},
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Annotations: &[]cyclonedx.Annotation{
				{
					BOMRef:   "annotation-1", // Same BOMRef - should merge
					Subjects: &[]cyclonedx.BOMReference{"component-a-updated"},
					Annotator: &cyclonedx.Annotator{
						Organization: &cyclonedx.OrganizationalEntity{Name: "Annotator B"}, // First input should win
					},
					Timestamp: "2023-02-01T00:00:00Z",
					Text:      "Updated annotation text",
				},
				{
					BOMRef:   "annotation-3",
					Subjects: &[]cyclonedx.BOMReference{"component-c"},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Annotations)
		assert.Len(t, *result.Annotations, 3) // annotation-1 merged, annotation-2 and annotation-3 separate

		// Convert to map for easier testing since order is not guaranteed
		annotationMap := make(map[string]cyclonedx.Annotation)
		for _, annotation := range *result.Annotations {
			annotationMap[annotation.BOMRef] = annotation
		}

		// annotation-1 should have merged with first input winning for non-empty fields
		assert.NotNil(t, annotationMap["annotation-1"].Subjects)
		assert.Len(t, *annotationMap["annotation-1"].Subjects, 2) // Both subjects merged
		assert.NotNil(t, annotationMap["annotation-1"].Annotator.Organization)
		assert.Equal(t, "Annotator A", annotationMap["annotation-1"].Annotator.Organization.Name) // First input wins
		assert.Equal(t, "2023-01-01T00:00:00Z", annotationMap["annotation-1"].Timestamp)          // First input wins
		assert.Equal(t, "Annotation A text", annotationMap["annotation-1"].Text)                  // First input wins

		assert.NotNil(t, annotationMap["annotation-2"].Subjects)
		assert.Equal(t, "component-b", string((*annotationMap["annotation-2"].Subjects)[0]))
		assert.NotNil(t, annotationMap["annotation-3"].Subjects)
		assert.Equal(t, "component-c", string((*annotationMap["annotation-3"].Subjects)[0]))
	})
}

func TestMergeBOM_Formulation(t *testing.T) {
	t.Run("merge formulation with BOMRef-based deduplication", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Formulation: &[]cyclonedx.Formula{
				{
					BOMRef: "formula-1",
					Components: &[]cyclonedx.Component{
						{Name: "Component A"},
					},
				},
				{
					BOMRef: "formula-2",
					Components: &[]cyclonedx.Component{
						{Name: "Component B"},
					},
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Formulation: &[]cyclonedx.Formula{
				{
					BOMRef: "formula-1", // Same BOMRef - should merge
					Components: &[]cyclonedx.Component{
						{Name: "Component C"},
					},
				},
				{
					BOMRef: "formula-3",
					Components: &[]cyclonedx.Component{
						{Name: "Component D"},
					},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Formulation)
		assert.Len(t, *result.Formulation, 3) // formula-1 merged, formula-2 and formula-3 separate

		// Convert to map for easier testing since order is not guaranteed
		formulaMap := make(map[string]cyclonedx.Formula)
		for _, formula := range *result.Formulation {
			formulaMap[formula.BOMRef] = formula
		}

		// formula-1 should have merged components
		assert.NotNil(t, formulaMap["formula-1"].Components)
		assert.Len(t, *formulaMap["formula-1"].Components, 2) // Component A and Component C

		// Find the components to verify they were merged
		componentNames := make([]string, 0)
		for _, comp := range *formulaMap["formula-1"].Components {
			componentNames = append(componentNames, comp.Name)
		}
		assert.Contains(t, componentNames, "Component A")
		assert.Contains(t, componentNames, "Component C")

		assert.Len(t, *formulaMap["formula-2"].Components, 1)
		assert.Equal(t, "Component B", (*formulaMap["formula-2"].Components)[0].Name)

		assert.Len(t, *formulaMap["formula-3"].Components, 1)
		assert.Equal(t, "Component D", (*formulaMap["formula-3"].Components)[0].Name)
	})
}

func TestMergeBOM_Declarations(t *testing.T) {
	t.Run("merge declarations", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Declarations: &cyclonedx.Declarations{
				Assessors: &[]cyclonedx.Assessor{
					{BOMRef: "assessor-1", ThirdParty: true},
				},
				Attestations: &[]cyclonedx.Attestation{
					{Summary: "Attestation A"},
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Declarations: &cyclonedx.Declarations{
				Assessors: &[]cyclonedx.Assessor{
					{BOMRef: "assessor-2", ThirdParty: false},
				},
				Claims: &[]cyclonedx.Claim{
					{Target: "target-1", Predicate: "predicate-1"},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Declarations)

		// Arrays should be merged
		assert.NotNil(t, result.Declarations.Assessors)
		assert.Len(t, *result.Declarations.Assessors, 2) // Both assessors

		assert.NotNil(t, result.Declarations.Attestations)
		assert.Len(t, *result.Declarations.Attestations, 1) // Only from first BOM

		assert.NotNil(t, result.Declarations.Claims)
		assert.Len(t, *result.Declarations.Claims, 1) // Only from second BOM
	})

	t.Run("fill nil declarations from second input", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Declarations: nil,
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Declarations: &cyclonedx.Declarations{
				Assessors: &[]cyclonedx.Assessor{
					{BOMRef: "assessor-1", ThirdParty: true},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Declarations)
		assert.NotNil(t, result.Declarations.Assessors)
		assert.Len(t, *result.Declarations.Assessors, 1)
		assert.Equal(t, "assessor-1", string((*result.Declarations.Assessors)[0].BOMRef))
		assert.True(t, (*result.Declarations.Assessors)[0].ThirdParty)
	})
}

func TestMergeBOM_Definitions(t *testing.T) {
	t.Run("merge definitions with BOMRef-based standard deduplication", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Definitions: &cyclonedx.Definitions{
				Standards: &[]cyclonedx.StandardDefinition{
					{
						BOMRef:      "standard-1",
						Name:        "Standard A",
						Version:     "1.0",
						Description: "Standard A description",
					},
					{
						BOMRef: "standard-2",
						Name:   "Standard B",
					},
				},
			},
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Definitions: &cyclonedx.Definitions{
				Standards: &[]cyclonedx.StandardDefinition{
					{
						BOMRef:      "standard-1", // Same BOMRef - should merge
						Name:        "Standard A Updated",
						Description: "Updated description", // First input should win
						Owner:       "Owner B",
					},
					{
						BOMRef: "standard-3",
						Name:   "Standard C",
					},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Definitions)
		assert.NotNil(t, result.Definitions.Standards)
		assert.Len(t, *result.Definitions.Standards, 3) // standard-1 merged, standard-2 and standard-3 separate

		// Convert to map for easier testing since order is not guaranteed
		standardMap := make(map[string]cyclonedx.StandardDefinition)
		for _, standard := range *result.Definitions.Standards {
			standardMap[standard.BOMRef] = standard
		}

		// standard-1 should have merged with first input winning for non-empty fields
		assert.Equal(t, "Standard A", standardMap["standard-1"].Name)                    // First input wins
		assert.Equal(t, "1.0", standardMap["standard-1"].Version)                        // First input wins
		assert.Equal(t, "Standard A description", standardMap["standard-1"].Description) // First input wins
		assert.Equal(t, "Owner B", standardMap["standard-1"].Owner)                      // Second input fills empty

		assert.Equal(t, "Standard B", standardMap["standard-2"].Name)
		assert.Equal(t, "Standard C", standardMap["standard-3"].Name)
	})

	t.Run("fill nil definitions from second input", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Definitions:  nil,
		}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Definitions: &cyclonedx.Definitions{
				Standards: &[]cyclonedx.StandardDefinition{
					{BOMRef: "standard-1", Name: "Standard B"},
				},
			},
		}

		result := MergeBom(a, b)

		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.NotNil(t, result.Definitions)
		assert.NotNil(t, result.Definitions.Standards)
		assert.Len(t, *result.Definitions.Standards, 1)
		assert.Equal(t, "Standard B", (*result.Definitions.Standards)[0].Name)
	})
}

func TestMergeBOM_EdgeCases(t *testing.T) {
	t.Run("empty BOMs", func(t *testing.T) {
		a := &cyclonedx.BOM{}
		b := &cyclonedx.BOM{}

		result := MergeBom(a, b)

		assert.NotNil(t, result)
		assert.Equal(t, "", result.SerialNumber)
		assert.Equal(t, 0, result.Version)
	})

	t.Run("one empty, one with data", func(t *testing.T) {
		a := &cyclonedx.BOM{}
		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Version:      1,
			Components: &[]cyclonedx.Component{
				{Name: "Component B"},
			},
		}

		result := MergeBom(a, b)

		assert.NotNil(t, result)
		assert.Equal(t, "urn:uuid:test-bom-b", result.SerialNumber) // Filled from second
		assert.Equal(t, 1, result.Version)                          // Filled from second
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "Component B", (*result.Components)[0].Name)
	})
}

func TestMergeBOM_RootComponentDependencies(t *testing.T) {
	t.Run("second BOM root dependencies transferred to first BOM root", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-a",
					Name:   "App A",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "root-a",
					Dependencies: &[]string{"existing-dep-a"},
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-b",
					Name:   "App B",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "root-b",
					Dependencies: &[]string{"dep-from-b1", "dep-from-b2"},
				},
			},
		}

		result := MergeBom(a, b)

		// Root component should be from first BOM
		assert.Equal(t, "root-a", result.Metadata.Component.BOMRef)

		// Find the root dependency
		var rootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-a" {
				rootDep = &dep
				break
			}
		}

		assert.NotNil(t, rootDep)
		assert.NotNil(t, rootDep.Dependencies)

		// Should have existing dependency + dependencies from second BOM's root
		assert.Len(t, *rootDep.Dependencies, 3)
		assert.Contains(t, *rootDep.Dependencies, "existing-dep-a")
		assert.Contains(t, *rootDep.Dependencies, "dep-from-b1")
		assert.Contains(t, *rootDep.Dependencies, "dep-from-b2")

		// Should NOT have the second BOM's root dependency (it's excluded to avoid duplication)
		var bRootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-b" {
				bRootDep = &dep
				break
			}
		}
		assert.Nil(t, bRootDep, "Second BOM's root dependency should be excluded to avoid duplication")
	})

	t.Run("no root dependency transfer when first BOM has no root", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			// No metadata/root component
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-b",
					Name:   "App B",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "root-b",
					Dependencies: &[]string{"dep-from-b1"},
				},
			},
		}

		result := MergeBom(a, b)

		// Dependencies should be merged as-is (no special handling)
		assert.NotNil(t, result.Dependencies)

		// Should have root-b dependency unchanged
		var bRootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-b" {
				bRootDep = &dep
				break
			}
		}
		assert.NotNil(t, bRootDep)
		assert.NotNil(t, bRootDep.Dependencies)
		assert.Contains(t, *bRootDep.Dependencies, "dep-from-b1")
	})

	t.Run("no root dependency transfer when roots have same BOMRef", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "same-root",
					Name:   "App A",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "same-root",
					Dependencies: &[]string{"existing-dep-a"},
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "same-root", // Same BOMRef
					Name:   "App B",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "same-root",
					Dependencies: &[]string{"dep-from-b1"},
				},
			},
		}

		result := MergeBom(a, b)

		// Should use regular dependency merging (both will be merged into one entry)
		var rootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "same-root" {
				rootDep = &dep
				break
			}
		}

		assert.NotNil(t, rootDep)
		assert.NotNil(t, rootDep.Dependencies)
		assert.Len(t, *rootDep.Dependencies, 2) // Regular merge behavior
		assert.Contains(t, *rootDep.Dependencies, "existing-dep-a")
		assert.Contains(t, *rootDep.Dependencies, "dep-from-b1")
	})

	t.Run("create new root dependency when first BOM root has no dependencies", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-a",
					Name:   "App A",
				},
			},
			// No dependencies array
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-b",
					Name:   "App B",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "root-b",
					Dependencies: &[]string{"dep-from-b1", "dep-from-b2"},
				},
			},
		}

		result := MergeBom(a, b)

		// Should create new root dependency for root-a
		var rootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-a" {
				rootDep = &dep
				break
			}
		}

		assert.NotNil(t, rootDep)
		assert.NotNil(t, rootDep.Dependencies)
		assert.Len(t, *rootDep.Dependencies, 2)
		assert.Contains(t, *rootDep.Dependencies, "dep-from-b1")
		assert.Contains(t, *rootDep.Dependencies, "dep-from-b2")
	})

	t.Run("deduplication when transferring dependencies", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-a",
					Name:   "App A",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "root-a",
					Dependencies: &[]string{"shared-dep", "unique-dep-a"},
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-b",
					Name:   "App B",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "root-b",
					Dependencies: &[]string{"shared-dep", "unique-dep-b"}, // shared-dep appears in both
				},
			},
		}

		result := MergeBom(a, b)

		// Find the root dependency
		var rootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-a" {
				rootDep = &dep
				break
			}
		}

		assert.NotNil(t, rootDep)
		assert.NotNil(t, rootDep.Dependencies)

		// Should have 3 unique dependencies (no duplicates)
		assert.Len(t, *rootDep.Dependencies, 3)
		assert.Contains(t, *rootDep.Dependencies, "shared-dep")
		assert.Contains(t, *rootDep.Dependencies, "unique-dep-a")
		assert.Contains(t, *rootDep.Dependencies, "unique-dep-b")
	})
}

func TestMergeBomAsDependency_Nil(t *testing.T) {
	tests := []struct {
		name     string
		a        *cyclonedx.BOM
		b        *cyclonedx.BOM
		expected *cyclonedx.BOM
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name: "first nil, second has value",
			a:    nil,
			b: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-b",
				Version:      1,
			},
			expected: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-b",
				Version:      1,
			},
		},
		{
			name: "first has value, second nil",
			a: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-a",
				Version:      1,
			},
			b: nil,
			expected: &cyclonedx.BOM{
				SerialNumber: "urn:uuid:test-bom-a",
				Version:      1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeBomAsDependency(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeBomAsDependency_RootComponent(t *testing.T) {
	t.Run("basic dependency addition", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Version:      1,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef:  "root-component-a",
					Name:    "Root Component A",
					Type:    cyclonedx.ComponentTypeApplication,
					Version: "1.0.0",
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Version:      1,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef:  "root-component-b",
					Name:    "Root Component B",
					Type:    cyclonedx.ComponentTypeLibrary,
					Version: "2.0.0",
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Check basic fields
		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.Equal(t, 1, result.Version)

		// Check root component is unchanged
		assert.NotNil(t, result.Metadata)
		assert.NotNil(t, result.Metadata.Component)
		assert.Equal(t, "root-component-a", result.Metadata.Component.BOMRef)
		assert.Equal(t, "Root Component A", result.Metadata.Component.Name)

		// Check that root component B was added to components
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "root-component-b", (*result.Components)[0].BOMRef)
		assert.Equal(t, "Root Component B", (*result.Components)[0].Name)

		// Check that dependency was created
		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 2) // root dependency + added component dependency

		// Find root dependency
		var rootDep *cyclonedx.Dependency
		var addedDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-component-a" {
				rootDep = &dep
			} else if dep.Ref == "root-component-b" {
				addedDep = &dep
			}
		}

		assert.NotNil(t, rootDep)
		assert.NotNil(t, addedDep)
		assert.NotNil(t, rootDep.Dependencies)
		assert.Len(t, *rootDep.Dependencies, 1)
		assert.Equal(t, "root-component-b", (*rootDep.Dependencies)[0])
	})

	t.Run("no root component in second BOM", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-component-a",
					Name:   "Root Component A",
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Components: &[]cyclonedx.Component{
				{Name: "Regular Component"},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Root component should be unchanged
		assert.Equal(t, "root-component-a", result.Metadata.Component.BOMRef)

		// Regular components should be merged
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "Regular Component", (*result.Components)[0].Name)

		// No new dependencies should be created for the root
		if result.Dependencies != nil {
			for _, dep := range *result.Dependencies {
				if dep.Ref == "root-component-a" {
					assert.Nil(t, dep.Dependencies, "Root component should not have dependencies added when second BOM has no root component")
				}
			}
		}
	})

	t.Run("no root component in first BOM", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-component-b",
					Name:   "Root Component B",
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Should add the component to components list
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "root-component-b", (*result.Components)[0].BOMRef)

		// Should add the dependency entry
		assert.NotNil(t, result.Dependencies)
		foundDep := false
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-component-b" {
				foundDep = true
				break
			}
		}
		assert.True(t, foundDep)
	})

	t.Run("root component without BOMRef", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name: "Root Component A",
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name: "Root Component B",
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Component should be added to components
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "Root Component B", (*result.Components)[0].Name)

		// No dependencies should be created since there's no BOMRef
		if result.Dependencies != nil {
			assert.Len(t, *result.Dependencies, 0)
		}
	})

	t.Run("existing root dependency", func(t *testing.T) {
		existingDep := "existing-dep"
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-component-a",
					Name:   "Root Component A",
				},
			},
			Dependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "root-component-a",
					Dependencies: &[]string{existingDep},
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-component-b",
					Name:   "Root Component B",
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Find the root dependency
		var rootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "root-component-a" {
				rootDep = &dep
				break
			}
		}

		assert.NotNil(t, rootDep)
		assert.NotNil(t, rootDep.Dependencies)
		assert.Len(t, *rootDep.Dependencies, 2) // existing + new dependency
		assert.Contains(t, *rootDep.Dependencies, existingDep)
		assert.Contains(t, *rootDep.Dependencies, "root-component-b")
	})
}

func TestMergeBomAsDependency_ComplexMerging(t *testing.T) {
	t.Run("merges all other BOM fields", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Components: &[]cyclonedx.Component{
				{Name: "Component A1"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "prop1", Value: "value1"},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Components: &[]cyclonedx.Component{
				{Name: "Component B1"},
			},
			Properties: &[]cyclonedx.Property{
				{Name: "prop2", Value: "value2"},
			},
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root-b",
					Name:   "Root B",
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Should have all components: original A components + root B component + B components
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 3)

		componentNames := make([]string, 0, 3)
		for _, comp := range *result.Components {
			componentNames = append(componentNames, comp.Name)
		}
		assert.Contains(t, componentNames, "Component A1")
		assert.Contains(t, componentNames, "Component B1")
		assert.Contains(t, componentNames, "Root B")

		// Should have merged properties
		assert.NotNil(t, result.Properties)
		assert.Len(t, *result.Properties, 2)
	})
}

func TestMergeBomAsDependency_SameRootComponent(t *testing.T) {
	t.Run("same BOMRef triggers regular merge", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Version:      1,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef:  "same-root",
					Name:    "My App",
					Type:    cyclonedx.ComponentTypeApplication,
					Version: "1.0.0",
				},
			},
			Components: &[]cyclonedx.Component{
				{Name: "Component A1"},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Version:      2,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef:  "same-root", // Same BOMRef
					Name:    "My App",
					Type:    cyclonedx.ComponentTypeApplication,
					Version: "1.0.0",
				},
			},
			Components: &[]cyclonedx.Component{
				{Name: "Component B1"},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Should behave like regular merge
		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber) // First input wins
		assert.Equal(t, 1, result.Version)                          // First input wins

		// Root component should remain the same (first input wins)
		assert.NotNil(t, result.Metadata)
		assert.NotNil(t, result.Metadata.Component)
		assert.Equal(t, "same-root", result.Metadata.Component.BOMRef)

		// Components should be merged normally (no duplicate root component)
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 2) // Not 3, because no duplicate root added

		componentNames := make([]string, 0, 2)
		for _, comp := range *result.Components {
			componentNames = append(componentNames, comp.Name)
		}
		assert.Contains(t, componentNames, "Component A1")
		assert.Contains(t, componentNames, "Component B1")

		// No self-dependency should be created
		if result.Dependencies != nil {
			for _, dep := range *result.Dependencies {
				if dep.Ref == "same-root" && dep.Dependencies != nil {
					assert.NotContains(t, *dep.Dependencies, "same-root", "Should not create self-dependency")
				}
			}
		}
	})

	t.Run("same name+version+purl triggers regular merge", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/myapp@1.0.0",
					Type:       cyclonedx.ComponentTypeApplication,
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",               // Same name
					Version:    "1.0.0",               // Same version
					PackageURL: "pkg:npm/myapp@1.0.0", // Same PURL
					Type:       cyclonedx.ComponentTypeApplication,
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Should behave like regular merge (first input wins)
		assert.Equal(t, "urn:uuid:test-bom-a", result.SerialNumber)
		assert.Equal(t, "MyApp", result.Metadata.Component.Name)

		// No duplicate root component should be added to components
		if result.Components != nil {
			for _, comp := range *result.Components {
				assert.NotEqual(t, "MyApp", comp.Name, "Root component should not be duplicated in components")
			}
		}
	})

	t.Run("different components create dependency", func(t *testing.T) {
		a := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-a",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef:  "app-a",
					Name:    "App A",
					Version: "1.0.0",
				},
			},
		}

		b := &cyclonedx.BOM{
			SerialNumber: "urn:uuid:test-bom-b",
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef:  "app-b", // Different BOMRef
					Name:    "App B", // Different name
					Version: "2.0.0", // Different version
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Should create dependency (not regular merge)
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1) // Root B component added

		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 2) // Root A dependency + Root B dependency

		// Find root A dependency
		var rootDep *cyclonedx.Dependency
		for _, dep := range *result.Dependencies {
			if dep.Ref == "app-a" {
				rootDep = &dep
				break
			}
		}
		assert.NotNil(t, rootDep)
		assert.NotNil(t, rootDep.Dependencies)
		assert.Contains(t, *rootDep.Dependencies, "app-b")
	})

	t.Run("partial match does not trigger same component logic", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:    "MyApp",
					Version: "1.0.0",
					// Missing PackageURL
				},
			},
		}

		b := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",               // Same name
					Version:    "1.0.0",               // Same version
					PackageURL: "pkg:npm/myapp@1.0.0", // Different (one missing)
				},
			},
		}

		result := MergeBomAsDependency(a, b)

		// Should create dependency, not do regular merge
		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1) // B's root component added
		assert.Equal(t, "MyApp", (*result.Components)[0].Name)
	})
}

func TestHasSameRootComponent(t *testing.T) {
	t.Run("same BOMRef", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "same-ref",
					Name:   "Different Name",
				},
			},
		}
		b := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "same-ref",
					Name:   "Another Name",
				},
			},
		}

		assert.True(t, hasSameRootComponent(a, b))
	})

	t.Run("same name+version+purl", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/myapp@1.0.0",
				},
			},
		}
		b := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/myapp@1.0.0",
				},
			},
		}

		assert.True(t, hasSameRootComponent(a, b))
	})

	t.Run("no root component in one BOM", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "test",
				},
			},
		}
		b := &cyclonedx.BOM{} // No metadata

		assert.False(t, hasSameRootComponent(a, b))
	})

	t.Run("nil metadata in one BOM", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "test",
				},
			},
		}
		b := &cyclonedx.BOM{
			Metadata: nil, // Explicitly nil metadata
		}

		assert.False(t, hasSameRootComponent(a, b))
	})

	t.Run("nil BOMs", func(t *testing.T) {
		assert.False(t, hasSameRootComponent(nil, nil))

		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{BOMRef: "test"},
			},
		}
		assert.False(t, hasSameRootComponent(a, nil))
		assert.False(t, hasSameRootComponent(nil, a))
	})

	t.Run("different BOMRefs", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "ref-a",
				},
			},
		}
		b := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "ref-b",
				},
			},
		}

		assert.False(t, hasSameRootComponent(a, b))
	})

	t.Run("partial name+version+purl match", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:    "MyApp",
					Version: "1.0.0",
					// Missing PackageURL
				},
			},
		}
		b := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/myapp@1.0.0",
				},
			},
		}

		assert.False(t, hasSameRootComponent(a, b))
	})

	t.Run("different versions", func(t *testing.T) {
		a := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/myapp@1.0.0",
				},
			},
		}
		b := &cyclonedx.BOM{
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:       "MyApp",
					Version:    "2.0.0", // Different version
					PackageURL: "pkg:npm/myapp@1.0.0",
				},
			},
		}

		assert.False(t, hasSameRootComponent(a, b))
	})
}
