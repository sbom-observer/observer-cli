package scanner

import (
	"path/filepath"

	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/types"
)

type ConfigRepoScanner struct{}

func (s *ConfigRepoScanner) Id() string {
	return "config"
}

func (s *ConfigRepoScanner) Priority() int {
	return 100
}

func (s *ConfigRepoScanner) Scan(target *ScanTarget) error {
	for filename := range target.Files {
		if filename == "observer.yml" || filename == "observer.yaml" {
			log.Info("parsing observer config file", "filename", filename)

			err := types.LoadConfig(&target.Config, filepath.Join(target.Path, filename))
			if err != nil {
				return err
			}

			log.Debug("loaded config", "config", target.Config)
		}
	}

	return nil
}
