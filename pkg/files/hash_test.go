package files

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFileSha256(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "empty file",
			content:  "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA-256 of empty string
		},
		{
			name:     "simple text",
			content:  "hello world",
			expected: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", // SHA-256 of "hello world"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test_file.txt")

			// Write test content to the file
			err := os.WriteFile(tmpFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Test the function
			hash, err := HashFileSha256(tmpFile)
			if err != nil {
				t.Fatalf("HashFileSha256() error = %v", err)
			}

			if hash != tt.expected {
				t.Errorf("HashFileSha256() = %v, want %v", hash, tt.expected)
			}
		})
	}
}

func TestHashFileSha256_NonExistentFile(t *testing.T) {
	// Test with a non-existent file
	hash, err := HashFileSha256("/path/to/non/existent/file.txt")

	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}

	if hash != "" {
		t.Errorf("Expected empty hash for non-existent file, got %v", hash)
	}
}

func TestHashFileSha256_LargeFile(t *testing.T) {
	// Create a larger file to test performance and correctness
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "large_file.txt")

	// Create content with repeated pattern
	content := make([]byte, 1024*1024) // 1MB file
	for i := range content {
		content[i] = byte(i % 256)
	}

	err := os.WriteFile(tmpFile, content, 0644)
	if err != nil {
		t.Fatalf("Failed to create large test file: %v", err)
	}

	// Test the function
	hash, err := HashFileSha256(tmpFile)
	if err != nil {
		t.Fatalf("HashFileSha256() error = %v", err)
	}

	// Verify that we get a valid SHA-256 hash (64 hex characters)
	if len(hash) != 64 {
		t.Errorf("Expected hash length of 64, got %d", len(hash))
	}

	// Test that calling it again gives the same result
	hash2, err := HashFileSha256(tmpFile)
	if err != nil {
		t.Fatalf("HashFileSha256() second call error = %v", err)
	}

	if hash != hash2 {
		t.Errorf("Hash not consistent: first call = %v, second call = %v", hash, hash2)
	}
}
