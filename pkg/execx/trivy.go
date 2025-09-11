package execx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sbom-observer/observer-cli/pkg/log"
)

func TrivyUpdateJavaDb() error {
	log.Debug("updating Trivy java database")

	_, extErr := Trivy("image", "--download-java-db-only")
	if extErr != nil {
		return fmt.Errorf("failed to update Trivy java vulnerability database: %w", extErr)
	}

	return nil
}

func TrivyAbsolutePath() (string, bool) {
	// First, try to find trivy in the same directory as the running executable
	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		trivyName := "trivy"
		if runtime.GOOS == "windows" {
			trivyName = "trivy.exe"
		}
		trivyPath := filepath.Join(execDir, trivyName)

		// Check if trivy exists in the executable directory
		if _, err := os.Stat(trivyPath); err == nil {
			log.Debug("found trivy in executable directory", "path", trivyPath)
			return trivyPath, true
		}
	}

	// Fall back to looking in PATH
	trivyPath, err := exec.LookPath("trivy")
	if err != nil {
		return "", false
	}
	log.Debug("found trivy in PATH", "path", trivyPath)
	return trivyPath, true
}

func Trivy(args ...string) (string, error) {
	log.Debug(fmt.Sprintf("running 'trivy %s'", strings.Join(args, " ")))

	trivyPath, found := TrivyAbsolutePath()
	if !found {
		log.Error("Trivy not found in $PATH")
		log.Print("Download and install Trivy from https://github.com/aquasecurity/trivy/releases")
		// TODO: add curl download instructions (use Github releases API?)
		os.Exit(1)
	}

	output, err := Exec(trivyPath, args...)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			log.Error("Trivy not found in $PATH")
			log.Print("Download and install Trivy from https://github.com/aquasecurity/trivy/releases")
			// TODO: add curl download instructions (use Github releases API?)
			os.Exit(1)
		}
	}

	return output, err
}

func TrivyUpdateDb() error {
	log.Debug("updating Trivy vulnerability database")

	_, extErr := Trivy("image", "--download-db-only")
	if extErr != nil {
		return fmt.Errorf("failed to update Trivy vulnerability database: %w", extErr)
	}

	return nil
}
