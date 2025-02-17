package builds

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sbom-observer/build-observer/pkg/types"
	"golang.org/x/exp/maps"
	"sbom.observer/cli/pkg/licenses"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/ospkgs"
)

// TODO: replace this with pkg/os/Package
type Package struct {
	Id              string
	Arch            string
	Name            string
	Version         string
	Dependencies    []string
	Files           []string
	IsSourcePackage bool
	Licenses        []licenses.License
	OSFamily        ospkgs.OSFamily
}

type BuildDependencies struct {
	Code       []Package
	Tools      []Package
	Transitive []Package
	// NOTE: Code and Tools might contain the same package
}

// export the imported type BuildObservations to keep the dependency to this package
type BuildObservations types.BuildObservations

// DependencyObservations filters the build observations to only include dependency related opens and execs
// this means external includes (i.e. #include <stdio.h> -> /usr/include/* etc) and compilers calls (/usr/bin/cc etc)
func DependencyObservations(observations BuildObservations) BuildObservations {
	includes := map[string]struct{}{}
	calls := map[string]struct{}{}

	for _, open := range observations.FilesOpened {
		if isExternalInclude(open) {
			includes[open] = struct{}{}
		}
	}

	for _, exec := range observations.FilesExecuted {
		if isCompilerCall(exec) {
			calls[exec] = struct{}{}
		}
	}

	result := BuildObservations{
		Start:            observations.Start,
		Stop:             observations.Stop,
		WorkingDirectory: observations.WorkingDirectory,
		FilesOpened:      maps.Keys(includes),
		FilesExecuted:    maps.Keys(calls),
	}

	// sort opens and executions
	sort.Strings(result.FilesOpened)
	sort.Strings(result.FilesExecuted)

	return result
}

func isExternalInclude(open string) bool {
	// TODO: should probable include everything in /usr/include and /usr/local/include as well
	return strings.Contains(open, "/usr") && strings.HasSuffix(open, ".h")
}

func isCompilerCall(exec string) bool {
	return strings.HasSuffix(exec, "/cc") ||
		strings.HasSuffix(exec, "/cc1") ||
		strings.HasSuffix(exec, "/gcc") ||
		strings.HasSuffix(exec, "/clang") ||
		strings.HasSuffix(exec, "/c++") ||
		strings.HasSuffix(exec, "/g++") ||
		strings.HasSuffix(exec, "/ld") ||
		strings.HasSuffix(exec, "/as") ||
		strings.HasSuffix(exec, "/go")
}

func ResolveDependencies(observations BuildObservations) (*BuildDependencies, error) {
	// figure out if running in a supported environment (dpkg based, rpm based )
	var packageManager = "unknown"

	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		packageManager = "dpkg"
	}

	for _, db := range []string{
		"var/lib/rpm/Packages",
		"var/lib/rpm/Packages.db",
		"var/lib/rpm/rpmdb.sqlite",
		"usr/lib/sysimage/rpm/Packages",
		"usr/lib/sysimage/rpm/Packages.db",
		"usr/lib/sysimage/rpm/rpmdb.sqlite",
	} {
		if _, err := os.Stat(db); err == nil {
			packageManager = "rpm"
		}
	}

	// figure out the distro
	osFamily, err := ospkgs.DetectOSFamily()
	if err != nil {
		return nil, fmt.Errorf("failed to detect OS family: %w", err)
	}

	log.Debugf("detected os family: %s %s", osFamily.Name, osFamily.Release)

	switch packageManager {
	case "dpkg":
		return resolveDpkgDependencies(osFamily, observations.FilesOpened, observations.FilesExecuted)
	default:
		return nil, fmt.Errorf("unsupported build environment '%s' - cannot resolve dependencies", packageManager)
	}
}
