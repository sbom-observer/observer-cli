//go:build !trivylink
// +build !trivylink

package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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

	info, err := os.Stat(trivyPath)
	if err != nil {
		return false
	}

	// on windows, the executable bit is not set, so just check if the file is a regular file
	if runtime.GOOS == "windows" {
		return info.Mode().IsRegular()
	}

	// check file binary is executable
	return info.Mode().Perm()&0111 != 0
}

func (s *TrivyScanner) LogInstructions() {
	log.Warn("Trivy is not installed (found in the current PATH) and is the preferred scanner for the current ecosystem. Please install it with instructions from https://trivy.dev/latest/getting-started/installation/")
}

func (s *TrivyScanner) Priority() int {
	return 1000
}

func (s *TrivyScanner) Scan(target *ScanTarget) error {
	// create args
	output := filepath.Join(os.TempDir(), fmt.Sprintf("sbom-%s-%s.cdx.json", ids.NextUUID(), time.Now().Format("20060102-150405")))
	args := []string{"fs", "--skip-db-update", "--skip-java-db-update", "--format", "cyclonedx", "--output", output}

	// skip subdirectories
	subs, err := subDirectories(target.Path)
	if err != nil {
		return fmt.Errorf("failed to read subdirectories in %s: %w", target.Path, err)
	}

	// Do not skip node_modules directory, so filter it out from subs
	subs = slices.DeleteFunc(subs, func(sub string) bool {
		return filepath.Base(sub) == "node_modules"
	})

	for _, sub := range subs {
		args = append(args, "--skip-dirs", sub)
	}

	// add path to scan
	args = append(args, target.Path)

	_, err = execx.Trivy(args...)
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

func subDirectories(path string) ([]string, error) {
	var dirs []string
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(path, entry.Name()))
		}
	}
	return dirs, nil
}
