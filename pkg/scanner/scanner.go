package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/sbom-observer/observer-cli/pkg/scanner/windows"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sbom-observer/observer-cli/pkg/log"
	"github.com/sbom-observer/observer-cli/pkg/types"
	"golang.org/x/exp/maps"
)

type Ecosystem string

const EcosystemGo Ecosystem = "go"
const EcosystemNpm Ecosystem = "npm"
const EcosystemNuget Ecosystem = "nuget"
const EcosystemPython Ecosystem = "python"
const EcosystemJava Ecosystem = "java"
const EcosystemJavaBinary Ecosystem = "java-binary"
const EcosystemRuby Ecosystem = "ruby"
const EcosystemPhp Ecosystem = "php"
const EcosystemRust Ecosystem = "rust"
const EcosystemConan Ecosystem = "conan"
const EcosystemElixir Ecosystem = "elixir"
const EcosystemDart Ecosystem = "dart"
const EcosystemSwift Ecosystem = "swift"
const EcosystemCrystal Ecosystem = "crystal"
const EcosystemBuildObserver Ecosystem = "build-observer"
const EcosystemObserver Ecosystem = "observer"
const EcosystemUnknownBinary Ecosystem = "binary"
const EcosystemSBOM Ecosystem = "sbom"
const EcosystemWindowsBinary Ecosystem = "windows-binary"

// TODO: expand

const EcosystemUnknown Ecosystem = "unknown"

var DefaultSkipDirs = types.SliceSet[string]{
	"node_modules",
	".git",
}

type ScanTarget struct {
	Path    string
	Files   map[string]Ecosystem
	Config  types.ScanConfig
	Results []*cdx.BOM
	Merged  *cdx.BOM
}

type RepoScanner interface {
	Id() string
	Priority() int
	Scan(*ScanTarget) error
	IsAvailable() bool
}

func FindScanTargets(initialTarget string, maxDepth uint) (map[string]*ScanTarget, error) {
	// resolve "." to the current working directory so we get sane naming
	if initialTarget == "." {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		initialTarget = cwd
	}

	initialTarget = filepath.Clean(initialTarget)
	initialDepth := strings.Count(initialTarget, string(os.PathSeparator))

	targets := map[string]*ScanTarget{}

	err := filepath.WalkDir(initialTarget, func(currentPath string, file fs.DirEntry, err error) error {
		depth := strings.Count(currentPath, string(os.PathSeparator)) - initialDepth

		if depth > int(maxDepth) {
			return filepath.SkipDir
		}

		if file == nil {
			return nil
		}

		if DefaultSkipDirs.Contains(file.Name()) {
			return filepath.SkipDir
		}

		// skip "hidden" dirs
		if file.IsDir() && file.Name() != "." && strings.HasPrefix(file.Name(), ".") {
			return filepath.SkipDir
		}

		// don't care about directories (yet)
		if file.IsDir() {
			return nil
		}

		relativePath := strings.TrimPrefix(currentPath, initialTarget)
		directoryPath := filepath.Dir(currentPath)

		// check if it's a "file-of-interest"
		ecosystem := IdentifyEcosystem(currentPath, relativePath, file.Name())
		log.Debug("identified ecosystem", "absolutePath", currentPath, "relativePath", relativePath, "fileName", file.Name(), "ecosystem", ecosystem)

		if ecosystem != EcosystemUnknown {
			target, found := targets[directoryPath]
			if !found {
				target = &ScanTarget{
					Path:  directoryPath,
					Files: map[string]Ecosystem{},
				}
				targets[directoryPath] = target
			}
			target.Files[file.Name()] = ecosystem
		}

		return nil
	})

	return targets, err
}

func IdentifyEcosystem(absolutePath string, relativePath string, fileName string) Ecosystem {
	switch fileName {
	case "Gemfile.lock":
		return EcosystemRuby
	case "composer.lock":
		return EcosystemPhp
	case "Cargo.lock":
		return EcosystemRust
	case "conan.lock":
		return EcosystemConan
	case "mix.lock":
		return EcosystemElixir
	case "pubspec.lock":
		return EcosystemDart
	case "Podfile.lock", "Package.resolved":
		return EcosystemSwift
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc", "yarn.lock", "pnpm-lock.yaml":
		return EcosystemNpm
	case "go.mod", "go.sum":
		return EcosystemGo
	case "packages.lock.json", "project.assets.json", "packages.config", ".deps.json", "Packages.props", "Directory.Packages.props":
		return EcosystemNuget
	case "pom.xml":
		return EcosystemJava
	case "build.gradle", "build.gradle.kts", "gradle.lockfile", "buildscript-gradle.lockfile", "settings.gradle", "settings.gradle.kts":
		return EcosystemJava
	case "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock":
		return EcosystemPython
	case "shard.lock", "shard.yml":
		return EcosystemCrystal
	case "observer.yml", "observer.yaml":
		return EcosystemObserver
	case "build-observations.json":
		return EcosystemBuildObserver
	}

	fileExtension := filepath.Ext(fileName)

	// java binary
	for _, ext := range []string{".jar", ".war", ".ear", ".jmod", ".par", ".sar", ".jpi", ".hpi", ".lpkg", ".nar"} {
		if fileExtension == ext {
			return EcosystemJavaBinary
		}
	}

	// windows binary
	for _, ext := range windows.PeExtensions {
		if fileExtension == ext {
			return EcosystemWindowsBinary
		}
	}

	// nuget
	if fileExtension == ".csproj" || fileExtension == ".vbproj" || fileExtension == ".fsproj" {
		return EcosystemNuget
	}

	// python conda
	if isConda(absolutePath) {
		return EcosystemPython
	}

	if isExecutableBinary(absolutePath) {
		return EcosystemUnknownBinary
	}

	if isSBOM(fileName) {
		return EcosystemSBOM
	}

	return EcosystemUnknown
}

func isExecutableBinary(fileName string) bool {
	fi, err := os.Stat(fileName)
	if err != nil {
		return false
	}

	if !filesystem.IsInterestingExecutable(simplefileapi.New(fileName, fi)) {
		return false
	}

	// ignore too large (500mb+) files
	if fi.Size() > 500*1024*1024 {
		log.Debug("skipping too large file", "fileName", fileName, "size", fi.Size())
		return false
	}

	return true
}

func isSBOM(fileName string) bool {
	// Format support based on: https://spdx.dev/resources/use/#documents
	// Format support based on: https://cyclonedx.org/specification/overview/#recognized-file-patterns
	extensions := []string{".spdx.json", ".spdx", ".spdx.yml", ".spdx.rdf", ".spdx.rdf.xml", ".cdx.json", ".cdx.xml", "bom.json", "bom.xml"}
	for _, ext := range extensions {
		if strings.HasSuffix(fileName, ext) {
			return true
		}
	}
	return false
}

func isConda(fileName string) bool {
	if !(strings.HasPrefix(fileName, "envs/") || strings.Contains(fileName, "/envs/")) {
		return false
	}

	if filepath.Ext(fileName) != ".json" {
		return false
	}

	if !strings.HasSuffix(filepath.Dir(fileName), "conda-meta") {
		return false
	}

	return true
}

func ScannersForTarget(target ScanTarget) []RepoScanner {
	scanners := map[string]RepoScanner{}
	for _, ecosystem := range target.Files {
		sfe := scannersForEcosystem(ecosystem)
		if len(sfe) == 0 {
			log.Debug("skipping unsupported ecosystem", "ecosystem", ecosystem)
			continue
		}
		for _, scanner := range sfe {
			if _, ok := scanners[scanner.Id()]; !ok {
				scanners[scanner.Id()] = scanner
			}
		}
	}

	effectiveScanners := maps.Values(scanners)

	slices.SortFunc(effectiveScanners, func(a, b RepoScanner) int {
		return a.Priority() - b.Priority()
	})

	for _, scanner := range effectiveScanners {
		log.Debug("scannersForTarget", "target", target.Files, "effectiveScanners", scanner.Id())
	}

	return effectiveScanners
}

func scannersForEcosystem(ecosystem Ecosystem) []RepoScanner {
	switch ecosystem {
	case EcosystemObserver:
		return []RepoScanner{&ConfigRepoScanner{}}
	case EcosystemBuildObserver:
		return []RepoScanner{&BuildObservationsScanner{}}
	case EcosystemNpm:
		return []RepoScanner{
			&ModuleNameScanner{},
			NewWithFallbackScanner(&TrivyScanner{}, NewDefaultScalibrRepoScanner()),
		}
	case EcosystemGo:
		return []RepoScanner{NewDefaultScalibrRepoScanner()}
	case EcosystemCrystal:
		return []RepoScanner{
			&CrystalShardScanner{},
			&scalibrRepoScanner{},
		}
	case EcosystemJavaBinary:
		return []RepoScanner{NewDefaultScalibrRepoScanner()}
	case EcosystemUnknownBinary:
		return []RepoScanner{
			&BinaryNameScanner{},
			NewDefaultScalibrRepoScanner(),
		}
	case EcosystemSBOM:
		return []RepoScanner{NewSBOMScalibrRepoScanner()}
	case EcosystemPython:
		return []RepoScanner{NewDefaultScalibrRepoScanner()}
	case EcosystemWindowsBinary:
		return []RepoScanner{
			&WindowsBinaryScanner{},
		}
	default:
		return []RepoScanner{
			NewWithFallbackScanner(&TrivyScanner{}, NewDefaultScalibrRepoScanner()),
		}
	}
}
