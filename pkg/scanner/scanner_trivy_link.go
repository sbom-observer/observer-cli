//go:build trivylink
// +build trivylink

package scanner

import (
	"context"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	trivycdx "github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
)

type TrivyScanner struct{}

func (s *TrivyScanner) Id() string {
	return "trivy"
}

func (s *TrivyScanner) Priority() int {
	return 1000
}

func (s *TrivyScanner) Scan(target *ScanTarget) error {
	bom, err := ScanRepoWithTrivy(target.Path)
	if err != nil {
		return fmt.Errorf("failed to scan the repository with Trivy: %w", err)
	}

	target.Results = append(target.Results, bom)
	return nil
}

func ScanRepoWithTrivy(path string) (*cyclonedx.BOM, error) {
	ctx := context.Background()

	opts := flag.Options{
		GlobalOptions:  flag.GlobalOptions{},
		AWSOptions:     flag.AWSOptions{},
		CacheOptions:   flag.CacheOptions{},
		CleanOptions:   flag.CleanOptions{},
		DBOptions:      flag.DBOptions{},
		ImageOptions:   flag.ImageOptions{},
		K8sOptions:     flag.K8sOptions{},
		LicenseOptions: flag.LicenseOptions{},
		MisconfOptions: flag.MisconfOptions{},
		ModuleOptions:  flag.ModuleOptions{},
		PackageOptions: flag.PackageOptions{
			IncludeDevDeps: false,
			PkgTypes:       []string{"os", "library"},
			PkgRelationships: []types.Relationship{
				types.RelationshipUnknown,
				types.RelationshipRoot,
				types.RelationshipWorkspace,
				types.RelationshipDirect,
				types.RelationshipIndirect,
			},
		},
		RegistryOptions: flag.RegistryOptions{},
		RegoOptions:     flag.RegoOptions{},
		RemoteOptions:   flag.RemoteOptions{},
		RepoOptions:     flag.RepoOptions{},
		ReportOptions:   flag.ReportOptions{},
		ScanOptions: flag.ScanOptions{
			Target:      path,
			SkipDirs:    nil,
			SkipFiles:   nil,
			OfflineScan: false,
			Scanners: trivytypes.Scanners{
				trivytypes.SBOMScanner,
			},
			FilePatterns:      nil,
			Parallel:          0,
			SBOMSources:       nil,
			RekorURL:          "https://rekor.sigstore.dev",
			DetectionPriority: "precise",
			Distro:            types.OS{},
		},
		SecretOptions:        flag.SecretOptions{},
		VulnerabilityOptions: flag.VulnerabilityOptions{},
		AppVersion:           "",
		DisabledAnalyzers:    nil,
	}
	//options, err := fsFlags.ToOptions(args)
	//if err != nil {
	//	return xerrors.Errorf("flag error: %w", err)
	//}

	r, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create a Trivy runner: %w", err)
	}
	defer r.Close(ctx)

	report, err := r.ScanFilesystem(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to scan the repository with Trivy: %w", err)
	}

	marshaler := trivycdx.NewMarshaler("dev")
	bom, err := marshaler.MarshalReport(ctx, report)
	if err != nil {
		return nil, fmt.Errorf("CycloneDX marshal error: %w", err)
	}

	if bom.Components != nil {
		for i := range *bom.Components {
			(*bom.Components)[i].Properties = nil
		}
	}

	return bom, nil
}
