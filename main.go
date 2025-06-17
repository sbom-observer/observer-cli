package main

import (
	"fmt"
	"os"

	"github.com/sbom-observer/observer-cli/pkg/cmd"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/types"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	types.Version = version
	types.Commit = commit
	types.Date = date

	// catch panic from log.Fatal and exit with error code 1
	defer func() {
		if r := recover(); r != nil {
			println()
			log.Print("")
			log.Error(fmt.Sprintf("%v", r))
			os.Exit(1)
		}
	}()

	cmd.Execute()
}
