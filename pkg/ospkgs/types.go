package ospkgs

const OSFamilyUnknown = "unknown"
const OSReleaseUnknown = "unknown"

const PackageManagerDebian = "deb"
const PackageManagerRPM = "rpm"

type OSFamily struct {
	Name           string
	Distro         string
	Release        string
	PackageManager string
}

type Package struct {
	Name          string
	Version       string
	Architecture  string
	Maintainer    string
	SourceName    string
	SourceVersion string
	License       string
	Provides      []string
	Dependencies  []string
}
