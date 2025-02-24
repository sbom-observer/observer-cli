package types

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ScanConfig struct {
	OutputTemplate string                         `yaml:"output,omitempty"`
	Component      ScanConfigComponent            `yaml:"component,omitempty"`
	Author         ScanConfigOrganizationalEntity `yaml:"author,omitempty"`
	Supplier       ScanConfigOrganizationalEntity `yaml:"supplier,omitempty"`
	Manufacturer   ScanConfigOrganizationalEntity `yaml:"manufacturer,omitempty"`
}

type ScanConfigOrganizationalEntity struct {
	Name     string              `yaml:"name,omitempty"`
	URL      string              `yaml:"url,omitempty"`
	Contacts []ScanConfigContact `yaml:"contacts,omitempty"`
}

type ScanConfigContact struct {
	Name  string `yaml:"name,omitempty"`
	Email string `yaml:"email,omitempty"`
	Phone string `yaml:"phone,omitempty"`
}

type ScanConfigComponent struct {
	Type        string `yaml:"type,omitempty"`
	Name        string `yaml:"name,omitempty"`
	Group       string `yaml:"group,omitempty"`
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
	License     string `yaml:"license,omitempty"`
}

func LoadConfig(config *ScanConfig,filename string) error {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return  err
	}

	err = yaml.Unmarshal(bs, &config)
	if err != nil {
		return  err
	}
	return nil
}
