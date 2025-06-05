package types

import (
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"gopkg.in/yaml.v3"
)

type ScanConfig struct {
	OutputTemplate string                    `yaml:"output,omitempty"`
	Component      cdx.Component             `yaml:"component,omitempty"`
	Author         cdx.OrganizationalContact `yaml:"author,omitempty"`
	Supplier       cdx.OrganizationalEntity  `yaml:"supplier,omitempty"`
	Manufacturer   cdx.OrganizationalEntity  `yaml:"manufacturer,omitempty"`
}

func LoadConfig(config *ScanConfig, filename string) error {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(bs, &config)
	if err != nil {
		return err
	}
	return nil
}
