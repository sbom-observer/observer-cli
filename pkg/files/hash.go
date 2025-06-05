package files

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// HashFileSha256 calculates the SHA-256 hash of a file
func HashFileSha256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
