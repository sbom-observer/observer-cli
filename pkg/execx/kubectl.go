package execx

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sbom-observer/observer-cli/pkg/log"
)

func Kubectl(args ...string) (string, error) {
	log.Debug(fmt.Sprintf("kubectl 'trivy %s'", strings.Join(args, " ")))

	output, err := Exec("kubectl", args...)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			log.Error("kubectl not found in $PATH")
			log.Print("Download and install kubectl from https://kubernetes.io/docs/tasks/tools/")
			// TODO: add curl download instructions
			os.Exit(1)
		}
	}

	return output, err
}
