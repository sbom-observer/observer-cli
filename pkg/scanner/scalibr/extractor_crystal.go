// Package scalibr extracts Crystal shard.lock files.
package scalibr

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
)

/*
shard.lock example:
version: 2.0
shards:
  ameba:
    git: https://github.com/crystal-ameba/ameba.git
    version: 1.6.4

  amq-protocol:
    git: https://github.com/cloudamqp/amq-protocol.cr.git
    version: 1.1.14

  amqp-client:
    git: https://github.com/cloudamqp/amqp-client.cr.git
    version: 1.3.0

  lz4:
    git: https://github.com/84codes/lz4.cr.git
    version: 1.0.0+git.commit.96d714f7593c66ca7425872fd26c7b1286806d3d

  mqtt-protocol:
    git: https://github.com/84codes/mqtt-protocol.cr.git
    version: 0.2.0+git.commit.3f82ee85d029e6d0505cbe261b108e156df4e598

  systemd:
    git: https://github.com/84codes/systemd.cr.git
    version: 2.0.0
*/

type shardLockPackage struct {
	Version string `yaml:"version"`
	Git     string `yaml:"git"`
}

type shardLockfile struct {
	Version string                      `yaml:"version"`
	Shards  map[string]shardLockPackage `yaml:"shards,omitempty"`
}

// CrystalShardLockExtractor extracts Crystal shard.lock files
type CrystalShardLockExtractor struct{}

// Name of the CrystalShardLockExtractor
func (e CrystalShardLockExtractor) Name() string { return "crystal/shard.lock" }

// Version of the CrystalShardLockExtractor
func (e CrystalShardLockExtractor) Version() int { return 0 }

// Requirements of the CrystalShardLockExtractor
func (e CrystalShardLockExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a shard.lock
func (e CrystalShardLockExtractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "shard.lock"
}

// Extract extracts Crystal shards from shard.lock files passed through the input.
func (e CrystalShardLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *shardLockfile
	if err := yaml.NewDecoder(input.Reader).Decode(&parsedLockfile); err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedLockfile.Shards))

	for name, pkg := range parsedLockfile.Shards {
		pkgDetails := &extractor.Inventory{
			Name:      name,
			Version:   pkg.Version,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Repo: pkg.Git,
			},
			// TODO: add dependency group metadata (ex. https://github.com/cloudamqp/lavinmq/blob/main/shard.yml)
			Metadata: osv.DepGroupMetadata{},
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this CrystalShardLockExtractor into a PURL.
func (e CrystalShardLockExtractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	var qualifiers purl.Qualifiers

	if i.SourceCode.Repo != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repository_url",
			Value: i.SourceCode.Repo,
		})
	}

	return &purl.PackageURL{
		Type:       "crystal",
		Name:       i.Name,
		Version:    i.Version,
		Qualifiers: qualifiers,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this CrystalShardLockExtractor.
func (e CrystalShardLockExtractor) Ecosystem(i *extractor.Inventory) string { return "Crystal" }

var _ filesystem.Extractor = CrystalShardLockExtractor{}
