package ospkgs

const OSFamilyUnknown = "unknown"
const OSReleaseUnknown = "unknown"

type OSFamily struct {
	Name    string
	Release string
}

type Package struct {
	Name          string
	Version       string
	Architecture  string
	Maintainer    string
	SourceName    string
	SourceVersion string
	Provides      []string
	Dependencies  []string
}
