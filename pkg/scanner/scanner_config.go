package scanner

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"sbom.observer/cli/pkg/log"
)

type ConfigRepoScanner struct{}

func (s *ConfigRepoScanner) Id() string {
	return "config"
}

func (s *ConfigRepoScanner) Priority() int {
	return 100
}

func (s *ConfigRepoScanner) Scan(target *ScanTarget) error {
	for filename, _ := range target.Files {
		if filename == "observer.yml" || filename == "observer.yaml" {
			log.Info("parsing observer config file", "filename", filename)
			bs, err := os.ReadFile(filepath.Join(target.Path, filename))
			if err != nil {
				return err
			}

			err = yaml.Unmarshal(bs, &target.Config)
			if err != nil {
				return err
			}

			log.Debug("loaded config", "config", target.Config)
		}
	}

	return nil
}
