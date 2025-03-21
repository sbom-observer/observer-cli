package execx

import (
	"errors"
	"fmt"
	"os"
	"sbom.observer/cli/pkg/log"
	"strings"
)

func Syft(args ...string) (string, error) {
	log.Debug(fmt.Sprintf("running 'syft %s'", strings.Join(args, " ")))

	output, err := Exec("syft", args...)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			log.Error("Syft not found in $PATH")
			log.Print("Download and install Syft from https://github.com/anchore/syft")
			// TODO: add curl download instructions (use Github releases API?)
			os.Exit(1)
		}
	}

	return output, err
}
