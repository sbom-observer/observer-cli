//go:build !trivylink
// +build !trivylink

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sbom.observer/cli/pkg/cdxutil"
	"sbom.observer/cli/pkg/execx"
	"sbom.observer/cli/pkg/ids"
	"sbom.observer/cli/pkg/log"
	"time"
)

type TrivyScanner struct{}

func (s *TrivyScanner) Id() string {
	return "trivy"
}

func (s *TrivyScanner) Priority() int {
	return 1000
}

func (s *TrivyScanner) Scan(target *ScanTarget) error {
	output := filepath.Join(os.TempDir(), fmt.Sprintf("sbom-%s-%s.cdx.json", ids.NextUUID(), time.Now().Format("20060102-150405")))

	_, err := execx.Trivy("fs", "--skip-db-update", "--skip-java-db-update", "--format", "cyclonedx", "--output", output, target.Path)
	if err != nil {
		var extCmdErr *execx.ExternalCommandError
		if errors.As(err, &extCmdErr) {
			log.Error("failed to create SBOM for repository with 'trivy' generator", "path", target.Path, "exitcode", extCmdErr.ExitCode)
			_, _ = fmt.Fprint(os.Stderr, "-- Trivy output --\n")
			_, _ = fmt.Fprint(os.Stderr, extCmdErr.StdErr)
			_, _ = fmt.Fprint(os.Stderr, "\n------------------\n")
			return err
		}

		log.Error("failed to create sbom for repository using Trivy", "err", err)
		return err
	}

	bom, err := cdxutil.ParseCycloneDX(output)
	if err != nil {
		return fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
	}

	// remove all properties from components
	if bom.Components != nil {
		for i := range *bom.Components {
			(*bom.Components)[i].Properties = nil
		}
	}

	target.Results = append(target.Results, bom)
	return nil
}
