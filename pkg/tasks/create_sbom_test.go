package tasks

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanArtifacts(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "scanartifacts_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test files with known content
	testFile1 := filepath.Join(tempDir, "test1.txt")
	testFile2 := filepath.Join(tempDir, "test2.bin")
	testDir := filepath.Join(tempDir, "testdir")

	err = os.WriteFile(testFile1, []byte("hello world"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(testFile2, []byte("binary content"), 0644)
	require.NoError(t, err)

	err = os.Mkdir(testDir, 0755)
	require.NoError(t, err)

	tests := []struct {
		name          string
		artifacts     []string
		expectedCount int
		expectedNames []string
		expectError   bool
		description   string
	}{
		{
			name:          "single file",
			artifacts:     []string{testFile1},
			expectedCount: 1,
			expectedNames: []string{"test1.txt"},
			expectError:   false,
			description:   "Should process a single valid file",
		},
		{
			name:          "multiple files",
			artifacts:     []string{testFile1, testFile2},
			expectedCount: 2,
			expectedNames: []string{"test1.txt", "test2.bin"},
			expectError:   false,
			description:   "Should process multiple valid files",
		},
		{
			name:          "space-separated files in single string",
			artifacts:     []string{testFile1 + " " + testFile2},
			expectedCount: 2,
			expectedNames: []string{"test1.txt", "test2.bin"},
			expectError:   false,
			description:   "Should handle space-separated file paths in a single artifact string",
		},
		{
			name:          "non-existent file",
			artifacts:     []string{filepath.Join(tempDir, "nonexistent.txt")},
			expectedCount: 0,
			expectedNames: []string{},
			expectError:   false,
			description:   "Should skip non-existent files without error",
		},
		{
			name:          "directory",
			artifacts:     []string{testDir},
			expectedCount: 0,
			expectedNames: []string{},
			expectError:   false,
			description:   "Should skip directories without error",
		},
		{
			name:          "mixed valid and invalid paths",
			artifacts:     []string{testFile1, filepath.Join(tempDir, "nonexistent.txt"), testDir, testFile2},
			expectedCount: 2,
			expectedNames: []string{"test1.txt", "test2.bin"},
			expectError:   false,
			description:   "Should process only valid files and skip invalid ones",
		},
		{
			name:          "empty artifacts list",
			artifacts:     []string{},
			expectedCount: 0,
			expectedNames: []string{},
			expectError:   false,
			description:   "Should handle empty artifacts list",
		},
		{
			name:          "whitespace handling",
			artifacts:     []string{"  " + testFile1 + "  ", " " + testFile2 + " "},
			expectedCount: 2,
			expectedNames: []string{"test1.txt", "test2.bin"},
			expectError:   false,
			description:   "Should trim whitespace from file paths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			components, err := scanArtifacts(tt.artifacts)

			if tt.expectError {
				assert.Error(t, err, tt.description)
				return
			}

			assert.NoError(t, err, tt.description)
			assert.Len(t, components, tt.expectedCount, "Expected %d components, got %d", tt.expectedCount, len(components))

			// Check component names
			actualNames := make([]string, len(components))
			for i, comp := range components {
				actualNames[i] = comp.Name
			}

			for _, expectedName := range tt.expectedNames {
				assert.Contains(t, actualNames, expectedName, "Expected component name %s not found", expectedName)
			}

			// Verify component properties for valid files
			for _, comp := range components {
				assert.Equal(t, cdx.ComponentTypeFile, comp.Type, "Component type should be File")
				assert.NotNil(t, comp.Hashes, "Component should have hashes")
				assert.Len(t, *comp.Hashes, 1, "Component should have exactly one hash")

				hash := (*comp.Hashes)[0]
				// Note: This tests the current behavior which has a bug - it uses SHA1 algorithm but SHA256 hash
				assert.Equal(t, cdx.HashAlgoSHA1, hash.Algorithm, "Hash algorithm should be SHA1 (current implementation)")
				assert.NotEmpty(t, hash.Value, "Hash value should not be empty")
				assert.Len(t, hash.Value, 64, "SHA256 hash should be 64 characters long")
			}
		})
	}
}
