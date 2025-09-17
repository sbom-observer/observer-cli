package mergex

import (
	"sort"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeService(t *testing.T) {
	t.Run("merge services with same BOMRef", func(t *testing.T) {
		authTrue := true
		trustFalse := false
		
		a := cyclonedx.Service{
			BOMRef:               "service-a",
			Name:                 "Service A",
			Group:                "com.example",
			Version:              "1.0.0",
			Description:          "First service description",
			Authenticated:        &authTrue,
			CrossesTrustBoundary: &trustFalse,
			Endpoints:            &[]string{"http://api.example.com", "https://api.example.com"},
			Properties: &[]cyclonedx.Property{
				{Name: "environment", Value: "production"},
				{Name: "team", Value: "platform"},
			},
		}
		
		authFalse := false
		trustTrue := true
		
		b := cyclonedx.Service{
			BOMRef:               "service-a",
			Name:                 "Service B", // Should not override first
			Group:                "com.different", // Should not override first
			Version:              "2.0.0", // Should not override first
			Description:          "Second service description", // Should not override first
			Authenticated:        &authFalse, // Should not override first
			CrossesTrustBoundary: &trustTrue, // Should not override first
			Endpoints:            &[]string{"https://api.example.com", "http://backup.example.com"}, // https://api.example.com is duplicate
			Properties: &[]cyclonedx.Property{
				{Name: "team", Value: "backend"}, // duplicate key - first should win
				{Name: "owner", Value: "john"}, // new key
			},
		}

		result := mergeService(a, b)

		assert.Equal(t, "service-a", result.BOMRef)
		assert.Equal(t, "Service A", result.Name) // First input wins
		assert.Equal(t, "com.example", result.Group) // First input wins
		assert.Equal(t, "1.0.0", result.Version) // First input wins
		assert.Equal(t, "First service description", result.Description) // First input wins
		
		// Boolean pointers - first input wins
		assert.NotNil(t, result.Authenticated)
		assert.True(t, *result.Authenticated)
		assert.NotNil(t, result.CrossesTrustBoundary)
		assert.False(t, *result.CrossesTrustBoundary)

		// Check endpoints are merged and deduplicated
		assert.NotNil(t, result.Endpoints)
		endpoints := *result.Endpoints
		sort.Strings(endpoints)
		assert.Len(t, endpoints, 3)
		assert.Equal(t, []string{"http://api.example.com", "http://backup.example.com", "https://api.example.com"}, endpoints)

		// Check properties are merged by key
		assert.NotNil(t, result.Properties)
		assert.Len(t, *result.Properties, 3) // 3 unique keys

		propMap := make(map[string]string)
		for _, prop := range *result.Properties {
			propMap[prop.Name] = prop.Value
		}
		assert.Equal(t, "production", propMap["environment"])
		assert.Equal(t, "platform", propMap["team"]) // First input wins
		assert.Equal(t, "john", propMap["owner"])
	})

	t.Run("merge services with nil fields", func(t *testing.T) {
		authTrue := true
		
		a := cyclonedx.Service{
			BOMRef:        "service-a",
			Name:          "Service A",
			Description:   "First service",
			Authenticated: &authTrue,
			Endpoints:     &[]string{"http://api.example.com"},
			Properties:    nil,
		}
		
		trustFalse := false
		
		b := cyclonedx.Service{
			BOMRef:               "service-a",
			Name:                 "Service B",
			Group:                "com.example", // Should be filled from second
			CrossesTrustBoundary: &trustFalse,
			Endpoints:            nil,
			Properties: &[]cyclonedx.Property{
				{Name: "environment", Value: "staging"},
			},
		}

		result := mergeService(a, b)

		assert.Equal(t, "service-a", result.BOMRef)
		assert.Equal(t, "Service A", result.Name) // First input wins
		assert.Equal(t, "com.example", result.Group) // Filled from second
		assert.Equal(t, "First service", result.Description) // From first

		// Boolean pointers from both inputs
		assert.NotNil(t, result.Authenticated)
		assert.True(t, *result.Authenticated) // From first
		assert.NotNil(t, result.CrossesTrustBoundary)
		assert.False(t, *result.CrossesTrustBoundary) // From second

		// Endpoints from first should be preserved
		assert.NotNil(t, result.Endpoints)
		assert.Equal(t, []string{"http://api.example.com"}, *result.Endpoints)

		// Properties from second should be included
		assert.NotNil(t, result.Properties)
		assert.Len(t, *result.Properties, 1)
		assert.Equal(t, "environment", (*result.Properties)[0].Name)
		assert.Equal(t, "staging", (*result.Properties)[0].Value)
	})

	t.Run("merge services with empty fields", func(t *testing.T) {
		a := cyclonedx.Service{
			BOMRef: "service-a",
			Name:   "Service A",
			// Group empty - should be filled from b
			// Version empty - should be filled from b
			Endpoints: &[]string{},
		}
		b := cyclonedx.Service{
			BOMRef:    "service-a",
			Name:      "Service B",
			Group:     "com.example", // Should fill empty field
			Version:   "1.5.0", // Should fill empty field
			Endpoints: &[]string{},
		}

		result := mergeService(a, b)

		assert.Equal(t, "service-a", result.BOMRef)
		assert.Equal(t, "Service A", result.Name) // First input wins
		assert.Equal(t, "com.example", result.Group) // Filled from second
		assert.Equal(t, "1.5.0", result.Version) // Filled from second
		assert.Nil(t, result.Endpoints) // Empty arrays result in nil
	})
}

func TestMergeServiceSlice(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := mergeServiceSliceInternal(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("first nil, second has values", func(t *testing.T) {
		b := &[]cyclonedx.Service{
			{
				BOMRef:      "service-b",
				Name:        "Service B",
				Group:       "com.example",
				Version:     "1.0.0",
				Description: "Service B description",
				Endpoints:   &[]string{"http://api-b.example.com"},
			},
		}

		result := mergeServiceSliceInternal(nil, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "service-b", (*result)[0].BOMRef)
		assert.Equal(t, "Service B", (*result)[0].Name)
		assert.Equal(t, "com.example", (*result)[0].Group)
		assert.Equal(t, "1.0.0", (*result)[0].Version)
		assert.Equal(t, []string{"http://api-b.example.com"}, *(*result)[0].Endpoints)
	})

	t.Run("merge slices with no overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Service{
			{
				BOMRef:      "service-a",
				Name:        "Service A",
				Group:       "com.example.a",
				Version:     "1.0.0",
				Endpoints:   &[]string{"http://api-a.example.com"},
			},
		}
		b := &[]cyclonedx.Service{
			{
				BOMRef:      "service-b",
				Name:        "Service B",
				Group:       "com.example.b",
				Version:     "2.0.0",
				Endpoints:   &[]string{"http://api-b.example.com"},
			},
		}

		result := mergeServiceSliceInternal(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 2)

		// Convert to map for easier testing since order is not guaranteed
		serviceMap := make(map[string]cyclonedx.Service)
		for _, svc := range *result {
			serviceMap[svc.BOMRef] = svc
		}

		assert.Equal(t, "Service A", serviceMap["service-a"].Name)
		assert.Equal(t, "com.example.a", serviceMap["service-a"].Group)
		assert.Equal(t, "1.0.0", serviceMap["service-a"].Version)
		assert.Equal(t, []string{"http://api-a.example.com"}, *serviceMap["service-a"].Endpoints)

		assert.Equal(t, "Service B", serviceMap["service-b"].Name)
		assert.Equal(t, "com.example.b", serviceMap["service-b"].Group)
		assert.Equal(t, "2.0.0", serviceMap["service-b"].Version)
		assert.Equal(t, []string{"http://api-b.example.com"}, *serviceMap["service-b"].Endpoints)
	})

	t.Run("merge slices with overlapping BOMRefs", func(t *testing.T) {
		a := &[]cyclonedx.Service{
			{
				BOMRef:      "service-a",
				Name:        "Service A",
				Group:       "com.example",
				Version:     "1.0.0",
				Description: "Original description",
				Endpoints:   &[]string{"http://api.example.com"},
				Properties: &[]cyclonedx.Property{
					{Name: "environment", Value: "production"},
				},
			},
			{
				BOMRef:      "service-b",
				Name:        "Service B",
				Version:     "1.0.0",
			},
		}
		b := &[]cyclonedx.Service{
			{
				BOMRef:      "service-a", // Same BOMRef as first
				Name:        "Service A Updated", // Should not override
				Group:       "com.different", // Should not override
				Version:     "2.0.0", // Should not override  
				Description: "Updated description", // Should not override
				Endpoints:   &[]string{"https://api.example.com", "http://backup.example.com"},
				Properties: &[]cyclonedx.Property{
					{Name: "environment", Value: "staging"}, // duplicate key - first should win
					{Name: "owner", Value: "team-a"}, // new key
				},
			},
			{
				BOMRef:      "service-c",
				Name:        "Service C",
				Version:     "1.0.0",
			},
		}

		result := mergeServiceSliceInternal(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 3) // service-a merged, service-b and service-c separate

		// Convert to map for easier testing since order is not guaranteed
		serviceMap := make(map[string]cyclonedx.Service)
		for _, svc := range *result {
			serviceMap[svc.BOMRef] = svc
		}

		// service-a should have merged fields and first input precedence
		assert.Equal(t, "Service A", serviceMap["service-a"].Name) // First input wins
		assert.Equal(t, "com.example", serviceMap["service-a"].Group) // First input wins
		assert.Equal(t, "1.0.0", serviceMap["service-a"].Version) // First input wins
		assert.Equal(t, "Original description", serviceMap["service-a"].Description) // First input wins

		// Check endpoints are merged
		endpoints := *serviceMap["service-a"].Endpoints
		sort.Strings(endpoints)
		assert.Equal(t, []string{"http://api.example.com", "http://backup.example.com", "https://api.example.com"}, endpoints)

		// Check properties are merged by key
		propMap := make(map[string]string)
		for _, prop := range *serviceMap["service-a"].Properties {
			propMap[prop.Name] = prop.Value
		}
		assert.Equal(t, "production", propMap["environment"]) // First input wins
		assert.Equal(t, "team-a", propMap["owner"]) // From second

		// service-b should remain unchanged
		assert.Equal(t, "Service B", serviceMap["service-b"].Name)
		assert.Equal(t, "1.0.0", serviceMap["service-b"].Version)

		// service-c should be added as-is
		assert.Equal(t, "Service C", serviceMap["service-c"].Name)
		assert.Equal(t, "1.0.0", serviceMap["service-c"].Version)
	})

	t.Run("merge slices with recursive services", func(t *testing.T) {
		a := &[]cyclonedx.Service{
			{
				BOMRef:  "parent-service",
				Name:    "Parent Service",
				Version: "1.0.0",
				Services: &[]cyclonedx.Service{
					{
						BOMRef:  "child-service-a",
						Name:    "Child Service A",
						Version: "1.0.0",
					},
				},
			},
		}
		b := &[]cyclonedx.Service{
			{
				BOMRef:  "parent-service", // Same BOMRef
				Name:    "Parent Service Updated", // Should not override
				Version: "2.0.0", // Should not override
				Services: &[]cyclonedx.Service{
					{
						BOMRef:  "child-service-a", // Same child BOMRef
						Name:    "Child Service A Updated", // Should not override
						Version: "2.0.0", // Should not override
						Group:   "com.example", // Should be filled
					},
					{
						BOMRef:  "child-service-b", // New child
						Name:    "Child Service B",
						Version: "1.0.0",
					},
				},
			},
		}

		result := mergeServiceSliceInternal(a, b)

		assert.NotNil(t, result)
		assert.Len(t, *result, 1) // One merged parent service

		parentService := (*result)[0]
		assert.Equal(t, "parent-service", parentService.BOMRef)
		assert.Equal(t, "Parent Service", parentService.Name) // First input wins
		assert.Equal(t, "1.0.0", parentService.Version) // First input wins

		// Check child services are merged
		assert.NotNil(t, parentService.Services)
		assert.Len(t, *parentService.Services, 2) // child-service-a merged, child-service-b added

		// Convert child services to map for easier testing
		childMap := make(map[string]cyclonedx.Service)
		for _, child := range *parentService.Services {
			childMap[child.BOMRef] = child
		}

		// child-service-a should be merged
		assert.Equal(t, "Child Service A", childMap["child-service-a"].Name) // First input wins
		assert.Equal(t, "1.0.0", childMap["child-service-a"].Version) // First input wins
		assert.Equal(t, "com.example", childMap["child-service-a"].Group) // Filled from second

		// child-service-b should be added as-is
		assert.Equal(t, "Child Service B", childMap["child-service-b"].Name)
		assert.Equal(t, "1.0.0", childMap["child-service-b"].Version)
	})

	t.Run("empty slices", func(t *testing.T) {
		a := &[]cyclonedx.Service{}
		b := &[]cyclonedx.Service{}

		result := mergeServiceSliceInternal(a, b)

		assert.Nil(t, result)
	})
}

func TestMergeServiceSlice_Immutability(t *testing.T) {
	t.Run("original slices are not modified", func(t *testing.T) {
		originalA := &[]cyclonedx.Service{
			{
				BOMRef:      "service-a",
				Name:        "Service A",
				Group:       "com.example",
				Version:     "1.0.0",
				Endpoints:   &[]string{"http://api.example.com"},
				Properties: &[]cyclonedx.Property{
					{Name: "environment", Value: "production"},
				},
			},
		}
		originalB := &[]cyclonedx.Service{
			{
				BOMRef:      "service-a", // Same BOMRef for merging
				Name:        "Service A Updated",
				Version:     "2.0.0",
				Endpoints:   &[]string{"https://api.example.com"},
				Properties: &[]cyclonedx.Property{
					{Name: "owner", Value: "team-a"},
				},
			},
		}

		// Create copies for comparison
		copyA := &[]cyclonedx.Service{
			{
				BOMRef:    (*originalA)[0].BOMRef,
				Name:      (*originalA)[0].Name,
				Group:     (*originalA)[0].Group,
				Version:   (*originalA)[0].Version,
				Endpoints: &[]string{(*(*originalA)[0].Endpoints)[0]},
				Properties: &[]cyclonedx.Property{
					{Name: (*(*originalA)[0].Properties)[0].Name, Value: (*(*originalA)[0].Properties)[0].Value},
				},
			},
		}
		copyB := &[]cyclonedx.Service{
			{
				BOMRef:    (*originalB)[0].BOMRef,
				Name:      (*originalB)[0].Name,
				Version:   (*originalB)[0].Version,
				Endpoints: &[]string{(*(*originalB)[0].Endpoints)[0]},
				Properties: &[]cyclonedx.Property{
					{Name: (*(*originalB)[0].Properties)[0].Name, Value: (*(*originalB)[0].Properties)[0].Value},
				},
			},
		}

		result := mergeServiceSliceInternal(originalA, originalB)

		// Verify original inputs were not modified
		assert.Equal(t, (*copyA)[0].BOMRef, (*originalA)[0].BOMRef)
		assert.Equal(t, (*copyA)[0].Name, (*originalA)[0].Name)
		assert.Equal(t, (*copyA)[0].Group, (*originalA)[0].Group)
		assert.Equal(t, (*copyA)[0].Version, (*originalA)[0].Version)
		assert.Equal(t, *(*copyA)[0].Endpoints, *(*originalA)[0].Endpoints)
		assert.Equal(t, (*(*copyA)[0].Properties)[0].Name, (*(*originalA)[0].Properties)[0].Name)

		assert.Equal(t, (*copyB)[0].BOMRef, (*originalB)[0].BOMRef)
		assert.Equal(t, (*copyB)[0].Name, (*originalB)[0].Name)
		assert.Equal(t, (*copyB)[0].Version, (*originalB)[0].Version)
		assert.Equal(t, *(*copyB)[0].Endpoints, *(*originalB)[0].Endpoints)
		assert.Equal(t, (*(*copyB)[0].Properties)[0].Name, (*(*originalB)[0].Properties)[0].Name)

		// Verify result is merged correctly
		assert.NotNil(t, result)
		assert.Len(t, *result, 1) // One merged service
		assert.Equal(t, "service-a", (*result)[0].BOMRef)
		assert.Equal(t, "Service A", (*result)[0].Name) // First input wins

		// Both endpoint arrays should be merged in result
		assert.NotNil(t, (*result)[0].Endpoints)
		assert.Len(t, *(*result)[0].Endpoints, 2) // Both unique endpoints

		// Both property arrays should be merged in result
		assert.NotNil(t, (*result)[0].Properties)
		assert.Len(t, *(*result)[0].Properties, 2) // Both unique properties
	})
}