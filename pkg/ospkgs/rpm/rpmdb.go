package rpm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"slices"

	rpmdb "github.com/erikvarga/go-rpmdb/pkg"
	"sbom.observer/cli/pkg/licenses"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/ospkgs"
)

var RpmDbPaths = []string{
	"/var/lib/rpm/Packages",
	"/var/lib/rpm/Packages.db",
	"/var/lib/rpm/rpmdb.sqlite",
	"/usr/lib/sysimage/rpm/Packages",
	"/usr/lib/sysimage/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/usr/share/rpm/Packages",
	"/usr/share/rpm/Packages.db",
	"/usr/share/rpm/rpmdb.sqlite",
}

type indexer struct {
	files    map[string]string
	packages map[string]*ospkgs.Package
	detector *licenses.Detector
}

func NewIndexer() *indexer {
	return &indexer{
		files:    make(map[string]string),
		packages: make(map[string]*ospkgs.Package),
		detector: licenses.NewLicenseDetector(),
	}
}

func (i *indexer) PackageNameForFile(filename string) (string, bool) {
	pkg, ok := i.files[filename]
	return pkg, ok
}

func (i *indexer) PackageForFile(filename string) (*ospkgs.Package, bool) {
	name, ok := i.files[filename]
	if !ok {
		return nil, false
	}

	pkg, ok := i.packages[name]

	if !ok {
		// name can contain an architecture 'linux-libc-dev:amd64', we only need the package name
		parts := strings.Split(name, ":")

		pkg, ok = i.packages[parts[0]]
	}

	return pkg, ok
}

func (i *indexer) PackageThatProvides(name string) (*ospkgs.Package, bool) {
	for _, pkg := range i.packages {
		if slices.Contains(pkg.Provides, name) {
			return pkg, true
		}
	}

	// name can be a filename, try to find the package that provides it
	return i.PackageForFile(name)
}

func (i *indexer) InstalledPackage(name string) *ospkgs.Package {
	pkg, ok := i.packages[name]
	if !ok {
		return nil
	}

	return pkg
}

//func (i *Indexer) InstalledPackages(pkg *ospkgs.Package) []string {
//	var installedFiles []string
//	for fileName, pkgName := range i.files {
//		if pkgName == pkg.Name {
//			installedFiles = append(installedFiles, fileName)
//		}
//	}
//	sort.Strings(installedFiles)
//	return installedFiles
//}

func (i *indexer) Create() error {
	log.Debug("creating rpm file index")
	start := time.Now()

	var pkgs []*rpmdb.PackageInfo
	for _, filename := range RpmDbPaths {
		if _, err := os.Stat(filename); err == nil {
			ps, err := i.loadDb(context.Background(), filename)
			if err != nil {
				return fmt.Errorf("failed to load rpm db: %w", err)
			}
			pkgs = append(pkgs, ps...)
		}
	}

	if len(pkgs) == 0 {
		return fmt.Errorf("no rpm db found")
	}

	for _, pkg := range pkgs {
		ospkg := &ospkgs.Package{
			Name:    pkg.Name,
			Version: pkg.Version,
			// Release:      pkg.Release,
			Architecture: pkg.Arch,
			// Maintainer:   pkg.Vendor,
			SourceName:    pkg.SourceRpm,
			SourceVersion: pkg.Version,
			License:       pkg.License,
			Provides:      pkg.Provides,
			Dependencies:  pkg.Requires,
		}

		if len(pkg.BaseNames) != len(pkg.DirIndexes) {
			// Debug: save package info as JSON for troubleshooting
			jsonData, err := json.MarshalIndent(pkg, "", "  ")
			if err != nil {
				log.Errorf("failed to marshal package %s to JSON: %v", pkg.Name, err)
			} else {
				if err := os.WriteFile("/tmp/debug.json", jsonData, 0644); err != nil {
					log.Errorf("failed to write debug JSON for package %s: %v", pkg.Name, err)
				}
			}
			log.Fatalf("package %s has %d basenames and %d dirindexes", pkg.Name, len(pkg.BaseNames), len(pkg.DirIndexes))
		}

		for idx, baseName := range pkg.BaseNames {
			i.files[path.Join(pkg.DirNames[pkg.DirIndexes[idx]], baseName)] = pkg.Name
		}

		i.packages[pkg.Name] = ospkg
	}

	took := time.Since(start) / time.Millisecond
	log.Debugf("indexed %d packages in %dms", len(pkgs), took)

	return nil
}

func (i *indexer) loadDb(ctx context.Context, path string) ([]*rpmdb.PackageInfo, error) {
	log.Debugf("loading rpm db from %s", path)

	db, err := rpmdb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	pkgs, err := db.ListPackagesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list packages: %w", err)
	}

	return pkgs, nil
}

func (i *indexer) LicensesForPackage(name string) ([]licenses.License, error) {
	var result []licenses.License
	for filename, pkgname := range i.files {
		// on rpm based systems licenses are typically stored in /usr/share/licenses/[package]/*
		if pkgname == name && strings.Contains(filename, "licenses") {
			// skip directories
			fi, err := os.Stat(filename)
			if err != nil || fi.IsDir() {
				continue
			}

			// NOTE: Running the license detector on the raw */copyright file is very naive but works surprisingly well
			//       but provides a lot of "false" positives for files not used by applications (e.g. gcc-12)
			lss, err := i.detector.DetectFile(filename)
			if err != nil {
				log.Errorf("failed to detect licenses for %s: %v", filename, err)
				continue
			}

			result = append(result, lss...)
		}
	}

	// handle -devel packages that are missing licenses
	if len(result) == 0 {
		if strings.HasSuffix(name, "-devel") {
			return i.LicensesForPackage(strings.TrimSuffix(name, "-devel"))
		}

		if pkg, ok := i.packages[name]; ok {
			return []licenses.License{
				{
					Expression: pkg.License,
					Declared:   true,
				},
			}, nil
		}
	}

	// de-duplicate found licenses
	var deduped []licenses.License
	for _, l := range result {
		found := false
		for _, r := range deduped {
			if l.Id == r.Id && l.Expression == r.Expression {
				found = true
				break
			}
		}
		if !found {
			deduped = append(deduped, l)
		}
	}

	return deduped, nil
}

// func (Extractor) Ecosystem(i *extractor.Inventory) string {
// 	m := i.Metadata.(*Metadata)
// 	if m.OSID == "rhel" {
// 		return "Red Hat"
// 	} else if m.OSID == "rocky" {
// 		return "Rocky Linux"
// 	} else {
// 		return ""
// 	}
// }
