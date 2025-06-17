package scanner

import (
	"path/filepath"
)

type BinaryNameScanner struct{}

func (s *BinaryNameScanner) Id() string {
	return "binaryName"
}

func (s *BinaryNameScanner) IsAvailable() bool {
	return true
}

func (s *BinaryNameScanner) Priority() int {
	return 200
}

func (s *BinaryNameScanner) Scan(target *ScanTarget) error {
	for filename, ecosystem := range target.Files {
		if ecosystem == EcosystemUnknownBinary {
			if target.Config.Component.Name == "" {
				target.Config.Component.Name = filepath.Base(filename)
			}
		}
	}

	return nil
}
