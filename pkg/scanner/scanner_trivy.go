//go:build !trivylink
// +build !trivylink

package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sbom-observer/observer-cli/pkg/cdxutil"
	"github.com/sbom-observer/observer-cli/pkg/execx"
	"github.com/sbom-observer/observer-cli/pkg/ids"
	"github.com/sbom-observer/observer-cli/pkg/log"
)

type TrivyScanner struct{}

func (s *TrivyScanner) Id() string {
	return "trivy"
}

func (s *TrivyScanner) IsAvailable() bool {
	// resolve absolute path to trivy binary
	trivyPath, err := exec.LookPath("trivy")
	if err != nil {
		return false
	}

	log.Debug("trivy path", "path", trivyPath)

	// check if trivy binary is executable
	info, err := os.Stat(trivyPath)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0111 != 0
}

func (s *TrivyScanner) LogInstructions() {
	log.Warn("Trivy is not installed (found in the current PATH) and is the preferred scanner for the current ecosystem. Please install it with instructions from https://trivy.dev/latest/getting-started/installation/")
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

	// remove properties from metadata
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		bom.Metadata.Component.Properties = nil
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
