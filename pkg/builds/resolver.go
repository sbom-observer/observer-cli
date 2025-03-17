package builds

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/exp/maps"
	"sbom.observer/cli/pkg/licenses"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/ospkgs"
	"sbom.observer/cli/pkg/ospkgs/dpkg"
	"sbom.observer/cli/pkg/ospkgs/rpm"
)

// TODO: move package

type PackageIndexer interface {
	Create() error
	PackageNameForFile(filename string) (string, bool)
	PackageForFile(filename string) (*ospkgs.Package, bool)
	PackageThatProvides(name string) (*ospkgs.Package, bool)
	InstalledPackage(name string) *ospkgs.Package
	LicensesForPackage(name string) ([]licenses.License, error)
}

func resolveRpmDependencies(osFamily ospkgs.OSFamily, opens []string, executions []string) (*BuildDependencies, error) {
	indexer := rpm.NewIndexer()
	return resolvePackageDependencies(osFamily, opens, executions, indexer)
}

func resolveDpkgDependencies(osFamily ospkgs.OSFamily, opens []string, executions []string) (*BuildDependencies, error) {
	indexer := dpkg.NewIndexer()
	return resolvePackageDependencies(osFamily, opens, executions, indexer)
}

func resolvePackageDependencies(osFamily ospkgs.OSFamily, opens []string, executions []string, indexer PackageIndexer) (*BuildDependencies, error) {
	log := log.Logger.WithPrefix("buildops")

	err := indexer.Create()
	if err != nil {
		return nil, err
	}

	code := map[string]*Package{}
	tools := map[string]*Package{}

	// parse filename form lines and deduplicate (more than one compiler might open the same file)
	includeFiles := map[string]struct{}{}
	for _, fileName := range opens {
		includeFiles[fileName] = struct{}{}
	}

	log.Debugf("resolving package attributions for %d observed files", len(includeFiles))

	// TODO: split this loop
	for fileName := range includeFiles {
		osPkg, found := indexer.PackageForFile(fileName)
		if !found {
			return nil, fmt.Errorf("failed to resolve package for file %s: not found", fileName)
		}

		// TODO: remove this package type
		pkg := Package{
			Id:           osPkg.Name + "@" + osPkg.Version,
			Name:         osPkg.Name,
			Version:      osPkg.Version,
			Arch:         osPkg.Architecture,
			Dependencies: osPkg.Dependencies,
			OSFamily:     osFamily,
		}

		licensesForPackage, err := indexer.LicensesForPackage(osPkg.Name)
		if err != nil {
			log.Error("failed to get licenses for package", "pkg", osPkg.Name, "err", err)
		}

		pkg.Licenses = licensesForPackage

		if len(pkg.Licenses) == 0 {
			log.Warn("no licenses found for package", "pkg", osPkg.Name)
		}

		// TODO: bug? what about multiple versions of the same package installed?
		code[pkg.Id] = &pkg

		if osPkg.SourceName != "" && (osPkg.Name != osPkg.SourceName || osPkg.Version != osPkg.SourceVersion) {
			sourcePackage := Package{
				Id:              fmt.Sprintf("src:%s@%s", osPkg.SourceName, osPkg.SourceVersion),
				Name:            osPkg.SourceName,
				Version:         osPkg.SourceVersion,
				IsSourcePackage: true,
			}

			pkg.Dependencies = append(pkg.Dependencies, sourcePackage.Id)

			if _, found := code[sourcePackage.Id]; !found {
				code[sourcePackage.Id] = &sourcePackage
			}
		}
	}

	for _, fileName := range executions {
		// resolve symlinks (/usr/bin/cc ->/etc/alternatives/cc -> /usr/bin/gcc -> /usr/bin/gcc-12 -> /usr/bin/x86_64-linux-gnu-gcc-12)
		fileName, err = filepath.EvalSymlinks(fileName)
		if err != nil {
			log.Warnf("failed to resolve symlinks for %s: %v", fileName, err)
		}

		osPkg, found := indexer.PackageForFile(fileName)
		if !found {
			return nil, fmt.Errorf("failed to resolve package for file %s: not found", fileName)
		}

		// TODO: remove this package type
		pkg := Package{
			Id:           osPkg.Name + "@" + osPkg.Version,
			Name:         osPkg.Name,
			Version:      osPkg.Version,
			Arch:         osPkg.Architecture,
			Dependencies: osPkg.Dependencies,
			Files:        []string{fileName},
			OSFamily:     osFamily,
		}

		licensesForPackage, err := indexer.LicensesForPackage(osPkg.Name)
		if err != nil {
			log.Error("failed to get licenses for package", "pkg", osPkg.Name, "err", err)
		}

		pkg.Licenses = licensesForPackage

		if len(pkg.Licenses) == 0 {
			log.Warn("no licenses found for package", "pkg", osPkg.Name)
		}

		tools[pkg.Id] = &pkg
	}

	// transitive dependencies
	var transitive []Package
	for _, pkg := range append(maps.Values(code), maps.Values(tools)...) {
		transitive = resolveTransitiveDependencies(pkg.Dependencies, transitive, osFamily, indexer)
	}

	// resolve ospkgs names -> pkg.Id
	for _, pkg := range append(maps.Values(code), maps.Values(tools)...) {
		var resolved []string
		for _, dep := range pkg.Dependencies {
			// rpmlib is a dummy package that is not a real package
			if strings.HasPrefix(dep, "rpmlib(") {
				continue
			}

			// ignore src: dependencies
			if strings.HasPrefix(dep, "src:") {
				continue
			}

			pkgThatProvides, found := indexer.PackageThatProvides(dep)
			if !found {
				log.Warn("failed to resolve package that provides", "pkg", pkg.Id, "dep", dep)
				continue
			}

			resolved = append(resolved, pkgThatProvides.Name+"@"+pkgThatProvides.Version)
		}
		pkg.Dependencies = resolved
	}

	for i := range transitive {
		var resolved []string
		for _, dep := range transitive[i].Dependencies {
			// rpmlib is a dummy package that is not a real package
			if strings.HasPrefix(dep, "rpmlib(") {
				continue
			}

			// ignore src: dependencies
			if strings.HasPrefix(dep, "src:") {
				continue
			}

			pkgThatProvides, found := indexer.PackageThatProvides(dep)
			if !found {
				log.Warn("failed to resolve package that provides (transitive)", "pkg", transitive[i].Id, "dep", dep)
				continue
			}

			resolved = append(resolved, pkgThatProvides.Name+"@"+pkgThatProvides.Version)
		}
		transitive[i].Dependencies = resolved
	}

	// gather results
	result := &BuildDependencies{}

	for _, pkg := range code {
		result.Code = append(result.Code, *pkg)
	}

	for _, pkg := range tools {
		result.Tools = append(result.Tools, *pkg)
	}

	result.Transitive = transitive

	slices.SortFunc(result.Code, func(a Package, b Package) int {
		if a.Name == b.Name {
			return cmp.Compare(a.Version, b.Version)
		}
		return cmp.Compare(a.Name, b.Name)
	})

	slices.SortFunc(result.Tools, func(a Package, b Package) int {
		if a.Name == b.Name {
			return cmp.Compare(a.Version, b.Version)
		}
		return cmp.Compare(a.Name, b.Name)
	})

	slices.SortFunc(result.Transitive, func(a Package, b Package) int {
		if a.Name == b.Name {
			return cmp.Compare(a.Version, b.Version)
		}
		return cmp.Compare(a.Name, b.Name)
	})

	return result, nil
}

func resolveTransitiveDependencies(names []string, collection []Package, family ospkgs.OSFamily, indexer PackageIndexer) []Package {
	for _, dep := range names {
		// rpmlib is a dummy package that is not a real package
		if strings.HasPrefix(dep, "rpmlib(") {
			continue
		}

		// ignore src: dependencies
		if strings.HasPrefix(dep, "src:") {
			continue
		}

		depPkg, found := indexer.PackageThatProvides(dep)
		if !found {
			log.Debug("dependency not found", "dep", dep)
			continue
		}

		if slices.ContainsFunc(collection, func(pkg Package) bool { return pkg.Name == depPkg.Name && pkg.Version == depPkg.Version }) {
			continue
		}

		osDependencyPackage := Package{
			Id:           fmt.Sprintf("%s@%s", depPkg.Name, depPkg.Version),
			Arch:         depPkg.Architecture,
			Name:         depPkg.Name,
			Version:      depPkg.Version,
			Dependencies: depPkg.Dependencies,
			OSFamily:     family,
		}

		collection = append(collection, osDependencyPackage)
		collection = resolveTransitiveDependencies(osDependencyPackage.Dependencies, collection, family, indexer)
	}

	return collection
}
