package scanner

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"sbom.observer/cli/pkg/log"
)

// CrystalShardScanner scans for Crystal shard.yml files and extracts the target's name and version.
type CrystalShardScanner struct{}

func (s *CrystalShardScanner) Id() string {
	return "crystalModule"
}

func (s *CrystalShardScanner) IsAvailable() bool {
	return true
}

func (s *CrystalShardScanner) Priority() int {
	return 200
}

func (s *CrystalShardScanner) Scan(target *ScanTarget) error {
	for filename, ecosystem := range target.Files {
		if filename == "shard.yml" {
			log.Debug("found shard.yml config file", "filename", filename, "ecosystem", ecosystem)

			contents := struct {
				Name    string `yaml:"name"`
				Version string `yaml:"version"`
			}{}

			f, err := os.Open(filepath.Join(target.Path, filename))
			if err != nil {
				return err
			}
			defer f.Close()

			err = yaml.NewDecoder(f).Decode(&contents)
			if err != nil {
				return err
			}

			if target.Config.Component.Name == "" {
				target.Config.Component.Name = contents.Name
			}

			if target.Config.Component.Version == "" {
				target.Config.Component.Version = contents.Version
			}

			log.Debug("loaded config", "config", target.Config)
		}
	}

	return nil
}
