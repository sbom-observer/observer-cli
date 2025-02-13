package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sbom.observer/cli/pkg/log"
)

type ModuleNameScanner struct{}

func (s *ModuleNameScanner) Id() string {
	return "moduleName"
}

func (s *ModuleNameScanner) Priority() int {
	return 200
}

func (s *ModuleNameScanner) Scan(target *ScanTarget) error {
	for filename, ecosystem := range target.Files {
		if filename == "package.json" {
			log.Debug("found package.json config file", "filename", filename, "ecosystem", ecosystem)

			contents := struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}{}

			f, err := os.Open(filepath.Join(target.Path, filename))
			if err != nil {
				return err
			}
			defer f.Close()

			err = json.NewDecoder(f).Decode(&contents)
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
