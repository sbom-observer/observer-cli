package main

import (
	"github.com/sbom-observer/observer-cli/pkg/cmd"
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

	cmd.Execute()
}
