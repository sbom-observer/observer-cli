package client

import (
	"encoding/json"
	"fmt"
	"time"
)

type Namespace struct {
	TenantId string `json:"tenantId"`
	Space    string `json:"space"`
}

type Component struct {
	Id         string            `json:"id"`
	PackageURL string            `json:"packageUrl,omitempty"` // canonical external identifier
	Type       string            `json:"type"`
	Version    string            `json:"version,omitempty"`
	Hashes     map[string]string `json:"hashes,omitempty"` // sha256, sha512, etc
	Name       string            `json:"name"`             // display name
	Group      string            `json:"group,omitempty"`  // display name
	Internal   bool              `json:"internal"`
}

type PolicyViolator struct {
	Id      string `json:"id"`
	Type    string `json:"type"`            // entity type component, environment, deployment etc
	Group   string `json:"group,omitempty"` // display name
	Name    string `json:"name"`            // display name
	Version string `json:"version"`         // display name
}

const (
	PolicyViolationActionIgnore    = "ignore"
	PolicyViolationActionFailBuild = "fail-build"
)

type PolicyViolation struct {
	// Id         string  `json:"id"`
	// PolicyId   string  `json:"policyId"`
	PolicyName string         `json:"policyName"` // display name
	Severity   float64        `json:"severity"`
	Message    string         `json:"message"`
	Details    string         `json:"details"`
	Link       string         `json:"link,omitempty"`
	Action     string         `json:"action,omitempty"` // recommended action
	Violator   PolicyViolator `json:"violator"`
}

type VulnerabilityAnalysis struct {
	Id            string    `json:"id"`
	Vulnerability string    `json:"vulnerability"`
	Affects       []string  `json:"affects"`
	State         string    `json:"state,omitempty"`
	Justification string    `json:"justification,omitempty"`
	Response      []string  `json:"response,omitempty"`
	Details       string    `json:"details,omitempty"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type SeveritySummary struct {
	// unknown
	NoRisk   int `json:"noRisk"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}

type SummaryLicense struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Count int    `json:"count"`
}

type SpeculateResponse struct {
	Namespace Namespace `json:"ns"`
	// Attestations              []Attestation                   `json:"attestations,omitempty"`
	Subject                   Component                       `json:"subject,omitempty"`
	ComponentsCount           int                             `json:"componentsCount,omitempty"`
	VulnerableComponentsCount int                             `json:"vulnerableComponentsCount,omitempty"`
	Violations                []PolicyViolation               `json:"violations,omitempty"`
	Vulnerabilities           []SpeculateVulnerabilitySummary `json:"vulnerabilities,omitempty"`
	VulnerabilitiesSummary    SeveritySummary                 `json:"vulnerabilitiesSummary,omitempty"`
	ViolationsSummary         SeveritySummary                 `json:"violationsSummary,omitempty"`
	LicenseSummary            []SummaryLicense                `json:"licenseSummary,omitempty"`
}

type SpeculateVulnerabilitySummary struct {
	VendorId        string                 `json:"vendorId"`
	PackageName     string                 `json:"packageName"`
	PackageVersion  string                 `json:"packageVersion"`
	Ecosystem       string                 `json:"ecosystem"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Published       *time.Time             `json:"published,omitempty"`    // Take from NVD
	LastModified    *time.Time             `json:"lastModified,omitempty"` // Take from NVD
	Severity        float64                `json:"severity"`
	EPSS            float32                `json:"epss,omitempty"`
	PatchAvailable  bool                   `json:"patchAvailable"`
	PatchedVersions []string               `json:"patchedVersions,omitempty"`
	Analysis        *VulnerabilityAnalysis `json:"analysis,omitempty"`
}

func (c *ObserverClient) AnalyzeSBOM(filename string) (*SpeculateResponse, error) {
	endpoint := fmt.Sprintf("%s/v1/%s/_analyze", c.Config.Endpoint, c.Config.Namespace)

	// if token is not set, use the public endpoint
	if c.Config.Token == "" {
		endpoint = fmt.Sprintf("%s/_analyzer/uploads?complete=true", c.Config.Endpoint)
	}

	resultBody, err := c.uploadFile(endpoint, filename)
	if err != nil {
		return nil, err
	}

	var result SpeculateResponse
	err = json.Unmarshal(resultBody, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal result %w", err)
	}

	return &result, nil
}
