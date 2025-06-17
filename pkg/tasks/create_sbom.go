package tasks

import (
	"fmt"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/cdxutil"
	"github.com/sbom-observer/observer-cli/pkg/files"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/scanner"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func CreateFilesystemSBOM(paths []string, flagDepth uint, flagMerge bool, flagArtifacts []string) ([]*cdx.BOM, error) {
	var err error

	if len(paths) < 1 {
		log.Fatal("the path to a source repository is required as an argument")
	}

	// find targets
	var targets []*scanner.ScanTarget
	{
		pathToTarget := map[string]*scanner.ScanTarget{}
		for _, arg := range paths {
			log.Debugf("finding scan targets for %s", arg)
			ts, err := scanner.FindScanTargets(arg, flagDepth)
			if err != nil {
				log.Fatal("failed to find scan targets", "err", err)
			}

			if len(ts) == 0 {
				log.Debugf("No targets found in %s", arg)
				continue
			}

			for path, target := range ts {
				if existingTarget, ok := pathToTarget[path]; ok {
					for file, ecosystem := range existingTarget.Files {
						target.Files[file] = ecosystem
					}
				}

				pathToTarget[path] = target
			}
		}

		for _, target := range pathToTarget {
			targets = append(targets, target)
		}

		// sort targets to make scanning is deterministic
		sort.Slice(targets, func(i, j int) bool {
			return len(targets[i].Path) < len(targets[j].Path)
		})
	}

	// TODO: remove
	for _, target := range targets {
		log.Debugf("found target %s -> %v", target.Path, target.Files)
	}

	if len(targets) == 0 {
		log.Fatal("no targets found")
	}

	// scan targets
	for _, target := range targets {
		log.Infof("Generating SBOM for '%s'", target.Path)
		log.Debug("Generating SBOM", "path", target.Path, "target", target.Files)

		for _, scanner := range scanner.ScannersForTarget(*target) {
			log.Debug("running scanner", "id", scanner.Id())
			err := scanner.Scan(target)
			if err != nil {
				log.Fatal("failed to create SBOM for repository", "path", target.Path, "err", err)
			}
		}

		// fallback to directory name if no name is set
		if target.Config.Component.Name == "" {
			target.Config.Component.Name = filepath.Base(target.Path)
		}

		// merge results and add metadata
		log.Debugf("merging %d BOMs for target %s", len(target.Results), target.Path)

		target.Merged, err = cdxutil.DestructiveMergeSBOMs(target.Config, target.Results)
		if err != nil {
			log.Fatal("failed to merge SBOMs for target", "target", target.Path, "err", err)
		}

		log.Debugf("merged %d BOMs for target %s -> %s@%s", len(target.Results), target.Path, target.Merged.Metadata.Component.Name, target.Merged.Metadata.Component.Version)
	}

	// TODO: implement --merge flag (and --merge-with-ref or --super)

	// merge to single file
	if flagMerge {
		var rootPath string
		var targetsToMerge []*scanner.ScanTarget

		for _, target := range targets {
			if rootPath == "" || len(target.Path) < len(rootPath) {
				rootPath = target.Path
			} else if !strings.HasPrefix(target.Path, rootPath) {
				log.Fatal("targets are not part of the same root path", "root", rootPath, "target", target.Path)
			}
			targetsToMerge = append(targetsToMerge, target)
		}

		// sort targets by path length
		sort.Slice(targetsToMerge, func(i, j int) bool {
			return len(targetsToMerge[i].Path) < len(targetsToMerge[j].Path)
		})

		var boms []*cdx.BOM
		for _, target := range targetsToMerge {
			boms = append(boms, target.Merged)
		}

		// TODO: replace with an additive merge
		merged, err := cdxutil.DestructiveMergeSBOMs(targetsToMerge[0].Config, boms)
		if err != nil {
			log.Fatal("failed to merge SBOMs for config", "config", targetsToMerge[0].Merged.Metadata.Component.Name, "err", err)
		}

		log.Debugf("merged %d BOMs to %s %s", len(boms), merged.Metadata.Component.Name, merged.Metadata.Component.Version)

		// add artifacts to the merged BOM
		if len(flagArtifacts) > 0 {
			artifacts, err := scanArtifacts(flagArtifacts)
			if err != nil {
				log.Fatal("failed to scan artifacts", "err", err)
			}

			log.Debugf("adding %d artifacts to merged BOM", len(artifacts))

			if len(artifacts) >= 0 {
				if merged.Metadata.Component == nil {
					log.Fatal("failed to add artifacts to merged BOM, the BOM is missing a root component", "err", err)
				}

				if merged.Metadata.Component.Components == nil {
					merged.Metadata.Component.Components = &[]cdx.Component{}
				}

				*merged.Metadata.Component.Components = append(*merged.Metadata.Component.Components, artifacts...)
			} else {
				log.Debug("no artifacts found")
			}
		}

		return []*cdx.BOM{merged}, nil
	}

	// return all results
	var results []*cdx.BOM
	for _, target := range targets {
		if target.Merged != nil {
			results = append(results, target.Merged)
		} else {
			results = append(results, target.Results...)
		}
	}

	return results, nil
}

func scanArtifacts(artifacts []string) ([]cdx.Component, error) {
	var components []cdx.Component

	for _, artifact := range artifacts {
		artifactPaths := strings.Split(artifact, " ")

		for _, path := range artifactPaths {
			path = strings.TrimSpace(path)

			// Check if file exists
			fileInfo, err := os.Stat(path)
			if err != nil {
				// skip files that don't exist
				continue
			}

			if fileInfo.IsDir() {
				// skip directories
				continue
			}

			hash, err := files.HashFileSha256(path)
			if err != nil {
				return nil, fmt.Errorf("failed to hash artifact file: %w", err)
			}

			// Create component for this artifact
			component := cdx.Component{
				Type: cdx.ComponentTypeFile,
				Name: filepath.Base(path),
				Hashes: &[]cdx.Hash{
					{
						Algorithm: cdx.HashAlgoSHA1,
						Value:     hash,
					},
				},
			}

			components = append(components, component)
		}
	}

	return components, nil
}
