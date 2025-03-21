package scanner

import (
	"path/filepath"
	"sbom.observer/cli/pkg/log"
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

			log.Debug("updated config", "config", target.Config)
		}
	}

	return nil
}
