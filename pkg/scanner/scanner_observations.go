package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"sbom.observer/cli/pkg/builds"
	"sbom.observer/cli/pkg/types"

	"sbom.observer/cli/pkg/log"
		cdx "github.com/CycloneDX/cyclonedx-go"
)

type BuildObservationsScanner struct{}

func (s *BuildObservationsScanner) Id() string {
	return "build-observations"
}

func (s *BuildObservationsScanner) IsAvailable() bool {
	return true
}

func (s *BuildObservationsScanner) Priority() int {
	return 1000
}

func (s *BuildObservationsScanner) Scan(target *ScanTarget) error {
	log := log.Logger.WithPrefix("build-observations")

	for filename, ecosystem := range target.Files {
		if filename == "build-observations.json" {
			log.Debug("found build observations file config file", "filename", filename, "ecosystem", ecosystem)

			f, err := os.Open(filepath.Join(target.Path, filename))
			if err != nil {
				return fmt.Errorf("failed to open build observations file: %w", err)
			}
			defer f.Close()

			var observations builds.BuildObservations
			decoder := json.NewDecoder(f)
			err = decoder.Decode(&observations)
			if err != nil {
				return fmt.Errorf("failed to decode build observations file: %w", err)
			}

			bom, err := ScanObservations(target.Config, observations)
			if err != nil {
				return fmt.Errorf("failed to scan build observations: %w", err)
			}

			target.Results = append(target.Results, bom)
		}
	}
	return nil
}

func ScanObservations(config types.ScanConfig, observations builds.BuildObservations) (*cdx.BOM, error) {
	log := log.Logger.WithPrefix("build-observations")

	log.Debugf("filtering dependencies from %d/%d observed build operations", len(observations.FilesOpened), len(observations.FilesExecuted))
	observations = builds.DependencyObservations(observations)

	dependencies, err := builds.ResolveDependencies(observations)
	if err != nil {
		return nil, fmt.Errorf("failed to parse build observations file: %w", err)
	}

	log.Debugf("resolved %d unique code dependencies", len(dependencies.Code))
	log.Debugf("resolved %d unique tool dependencies", len(dependencies.Tools))
	log.Debugf("resolved %d unique transitive dependencies", len(dependencies.Transitive))

	bom, err := builds.GenerateCycloneDX(dependencies, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CycloneDX BOM: %w", err)
	}

	// report unresolved files
	if len(dependencies.UnresolvedFiles) > 0 {
		// log.Warn("scanning build observations found unattributed files", "observations", filepath.Join(target.Path, filename))
		for _, file := range dependencies.UnresolvedFiles {
			log.Warn("unattributed file", "file", file)
		}
	}


	return bom, nil
}
