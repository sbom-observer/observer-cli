package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/binary/platform"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	filesystemextractors "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	cdxe "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	spdxe "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scalibr/extractor/standalone"
	sfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
	"sbom.observer/cli/pkg/log"
	localextractors "sbom.observer/cli/pkg/scanner/scalibr"
)

type ScalibrRepoScanner struct {
	includeDevDependencies bool
}

func (s *ScalibrRepoScanner) Id() string {
	return "scalibr"
}

func (s *ScalibrRepoScanner) Priority() int {
	return 1000
}

func (s *ScalibrRepoScanner) Scan(target *ScanTarget) error {
	capabilities := &plugin.Capabilities{
		OS:            platform.OS(),
		Network:       plugin.NetworkOnline,
		DirectFS:      true,
		RunningSystem: true,
	}

	extractors, err := filesystemextractors.ExtractorsFromNames([]string{"default"})
	if err != nil {
		return fmt.Errorf("failed to get default extractors: %w", err)
	}

	extractors = append(extractors, localextractors.CrystalShardLockExtractor{})

	var standaloneExtractors []standalone.Extractor = nil
	var detectors []detector.Detector = nil
	extractors, standaloneExtractors, detectors = filterByCapabilities(extractors, standaloneExtractors, detectors, capabilities)

	var filesToScan []string
	for f := range target.Files {
		filesToScan = append(filesToScan, filepath.Join(target.Path, f))
	}

	log.Debugf("Scanning path %s", target.Path)
	log.Debugf("Scanning %v files", filesToScan)

	config := &scalibr.ScanConfig{
		Capabilities:         capabilities,
		FilesystemExtractors: extractors,
		// standalone should be used for systems (i.e. Windows)
		// Detectors none (inventory -> findings)
		ScanRoots:      []*sfs.ScanRoot{sfs.RealFSScanRoot(target.Path)},
		FilesToExtract: filesToScan,
	}

	log.Infof(
		"Running scan with %d extractors and %d detectors",
		len(config.FilesystemExtractors)+len(config.StandaloneExtractors), len(config.Detectors),
	)

	// TODO: context timeout
	scalibrResult := scalibr.New().Scan(context.Background(), config)

	log.Debugf("Scan status: %v", scalibrResult.Status)

	if scalibrResult.Status.Status != plugin.ScanStatusSucceeded {
		return fmt.Errorf("scan wasn't successful: %s", scalibrResult.Status.FailureReason)
	}

	bom := cyclonedx.NewBOM()

	// this metadata will probably be overwritten by the next scanner or merge process
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Component: &cyclonedx.Component{
			BOMRef: uuid.New().String(),
			Type:   cyclonedx.ComponentTypeApplication,
			Name:   filepath.Base(target.Path),
		},
		//Tools: &cyclonedx.ToolsChoice{
		//	Components: &[]cyclonedx.Component{
		//		{
		//			Type: cyclonedx.ComponentTypeApplication,
		//			Name: "SCALIBR",
		//			ExternalReferences: &[]cyclonedx.ExternalReference{
		//				{
		//					URL:  "https://github.com/google/osv-scalibr",
		//					Type: cyclonedx.ERTypeWebsite,
		//				},
		//			},
		//		},
		//	},
		//},
	}

	// add inventory to bom
	scalibrToCycloneDX(bom, scalibrResult, s.includeDevDependencies)

	target.Results = append(target.Results, bom)

	// TODO: remove
	//enc := json.NewEncoder(os.Stdout)
	//enc.SetIndent("", "  ")
	//enc.Encode(bom)
	//
	//fmt.Println("------------------- TEMP BREAK -------------------")
	//os.Exit(1)

	return nil
}

func filterByCapabilities(
	f []filesystem.Extractor, s []standalone.Extractor,
	d []detector.Detector, capab *plugin.Capabilities) (
	[]filesystem.Extractor, []standalone.Extractor, []detector.Detector) {
	ff := make([]filesystem.Extractor, 0, len(f))
	sf := make([]standalone.Extractor, 0, len(s))
	df := make([]detector.Detector, 0, len(d))
	for _, ex := range f {
		if err := plugin.ValidateRequirements(ex, capab); err == nil {
			ff = append(ff, ex)
		}
	}
	for _, ex := range s {
		if err := plugin.ValidateRequirements(ex, capab); err == nil {
			sf = append(sf, ex)
		}
	}
	for _, det := range d {
		if err := plugin.ValidateRequirements(det, capab); err == nil {
			df = append(df, det)
		}
	}
	return ff, sf, df
}

func scalibrToCycloneDX(bom *cyclonedx.BOM, r *scalibr.ScanResult, includeDevDependencies bool) {
	comps := make([]cyclonedx.Component, 0, len(r.Inventories))

NextInventory:
	for _, i := range r.Inventories {
		// skip dev
		if !includeDevDependencies {
			if i.Metadata != nil {
				if m, ok := i.Metadata.(osv.DepGroupMetadata); ok {
					if slices.Contains(m.DepGroupVals, "dev") {
						continue NextInventory
					}
				}
			}
		}

		pkg := cyclonedx.Component{
			BOMRef:  uuid.New().String(),
			Type:    cyclonedx.ComponentTypeLibrary,
			Name:    (*i).Name,
			Version: (*i).Version,
		}

		if p := toPURL(i); p != nil {
			pkg.PackageURL = p.String()
			pkg.BOMRef = pkg.PackageURL
		}

		if cpes := extractCPEs(i); len(cpes) > 0 {
			pkg.CPE = cpes[0]
		}

		if len((*i).Locations) > 0 {
			occ := make([]cyclonedx.EvidenceOccurrence, 0, len(((*i).Locations)))
			for _, loc := range (*i).Locations {
				occ = append(occ, cyclonedx.EvidenceOccurrence{
					Location: loc,
				})
			}
			pkg.Evidence = &cyclonedx.Evidence{
				Occurrences: &occ,
			}
		}
		comps = append(comps, pkg)
	}
	bom.Components = &comps

	var allRefs []string
	for _, comp := range comps {
		allRefs = append(allRefs, comp.BOMRef)
	}

	// add a top level dependency section
	bom.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref:          bom.Metadata.Component.BOMRef,
			Dependencies: &allRefs,
		},
	}
}

func toPURL(i *extractor.Inventory) *purl.PackageURL {
	return i.Extractor.ToPURL(i)
}

func extractCPEs(i *extractor.Inventory) []string {
	// Only the two SBOM inventory types support storing CPEs (i.e. scanning existing SBOMs).
	if m, ok := i.Metadata.(*spdxe.Metadata); ok {
		return m.CPEs
	}
	if m, ok := i.Metadata.(*cdxe.Metadata); ok {
		return m.CPEs
	}
	return nil
}
