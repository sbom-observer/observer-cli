# Observer -  SBOM Generator and tooling

**observer** is a command-line-tool that allows you to create Software Bill of Materials (SBOMs) in CyclonDx format from source code or container images.

This tool is primarily a *meta* scanner, meaning that in most cases it delegates the actual generation to other libraries, or external tools, depending the the scan-target. 

We aim to keep an opinionated list of scanners that we believe are the most accurate and useful per ecosystem (e.g. Go, JavaScript, Python, Java, etc) or type of scan target (e.g. filesystem, container image, k8s cluster etc).

The tool currently delegates the scanning to [osv-scalibr](https://github.com/google/osv-scalibr) (as a library) and [Trivy](https://github.com/aquasecurity/trivy) (needs to be installed separately).

The tool is designed to be extensible, so we may add support for other scanners as well.

## Usage

```
Usage:
  observer [command]

Available Commands:
  build       Observe a build process and optionally generate a CycloneDX SBOM
  completion  Generate the autocompletion script for the specified shell
  diff        Compare two SBOMs and show the differences
  fs          Create an SBOM from a filesystem directory (source repository, including monorepos) or list of files
  help        Help about any command
  image       Create an SBOM for a container image
  k8s         Create an environment snapshot, and optionally SBOMs, of a k8s cluster.
  upload      Upload one or more attestations (SBOMs) to https://sbom.observer

Flags:
      --debug     Enable debug logging (implies silent mode)
  -h, --help      help for observer
      --silent    Silent mode (no progress bars)
  -v, --version   version for observer

Use "observer [command] --help" for more information about a command.
```

## Supported ecosystems

The following ecosystems and scan targets are supported:

- Go (modules, binaries)
- JavaScript (npm, yarn, pnpm)
- Python (pip, pyproject.toml, poetry, uv)
- Java (maven, gradle)
- Dotnet (nuget)
- Ruby (gem)
- PHP (composer)
- Rust (cargo)
- Conan
- Elixir (mix, hex)
- Dart (pub)
- Swift (swift build)
- Crystal (shards)
- C/C++ ([build-observer](https://github.com/sbom-observer/build-observer))
- SBOM (CycloneDX, SPDX)
- Container images
- Kubernetes (kubectl)


## Monorepos
For monorepos, the `fs` command will scan each component in the repository and create a separate SBOM for each component (subdirectory).

When there is multiple components in the _same_ folder (e.g. go.mod + package-lock.json), the scanner will merge the SBOMs into a single file.

## SBOM Metadata files

You can configure the SBOM metadata fields (root component, supplier, etc) by adding a `observer.yaml` file in the root of the repository (or the root of each component in a monorepo).

Example:
```yaml
component:
    type: application
    name: my-application
    group: my-group
    version: 1.0.0
    description: Description of component
    license: MIT
supplier:
    name: Supplier Name
    url: https://example.com
    contacts:
        - name: John Doe
          email: john.doe@example.com
          phone: "123"
```

## Creating SBOMs for C/C++ projects (and mixed-language projects)

Creating accurate SBOMs for C/C++ projects is challenging, because the build process often involves multiple steps and tools, and the dependencies are often installed as OS packages, and not via an ecosystem package manager.

To address this, we have created a library called [build-observer](https://github.com/sbom-observer/build-observer) that can watch the build process and create a log of all files that are read, written or executed during the build.

This log can then be used by the `observer` tool to create an SBOM using dependency information from OS package manager.

Using a combination of [build-observer](https://github.com/sbom-observer/build-observer) and the `fs` command, you can create accurate build-time SBOMs for C/C++ projects. 

This also works for mixed-language projects, like a Go project that uses CGO to include C code, or a _npm_ project that uses `node-gyp` to include C++ code.

For mixed-language projects, the `fs` command will create multiple SBOMs during scanning and then merge them into a single SBOM.

> [!IMPORTANT]
> Currently the scanner can only resolve observed dependencies when they are installed on the build machine using the package manager of the OS.
> **Initially only apt and rpm based linux systems are supported**, but we plan to add support for more package managers in the future. 
>
>We also plan support for Windows and FreeBSD in the future.

Example of creating an SBOM for a C/C++ project in a single step:

```bash
~/src/nginx-1.26.0 $ sudo observer build -u cicd -b nginx.cdx.json -- make
```

This will create a CycloneDX BOM `nginx.cdx.json` that includes all the dependencies of the project.

> [!IMPORTANT]
> The build-observer process requires root privileges to load the eBPF program into the kernel. Use the `-u` flag to drop privileges before executing the build.


Example of observering the build and creating the SBOM in a separate step:

```bash
~/src/nginx-1.26.0 $ sudo observer build -u cicd -- make
...
~/src/nginx-1.26.0 $ observer fs -o ./sboms nginx.cdx.json .
...
INFO buildops: parsing build observations file build-observations.out
...
INFO wrote CycloneDX BOM to ./sboms/nginx-1.26.0.bom.xml
...
```


Example of a mixed project:
```bash
~/src/webapp $ sudo observer build -u cicd -- npm install --build-from-source
...
~/src/webapp $ observer fs -o ./sboms .
...
INFO buildops: parsing build observations file build-observations.out
...
INFO wrote CycloneDX BOM to ./sboms/webapp-0.0.0.bom.xml
~/src/webapp $
```

### What is included in the generated SBOM?

There are many uses for build-time SBOMS but, in our opinion, for most use-cases all steps and tools that **provide material for the final artifact** should be included.

This includes:
- Libraries
- Standard libraries and runtimes (example: glibc, Go standard library and runtime, etc)
- Compilers, assemblers, linkers, etc
- Code generators, transformers, etc

There have been a number of supply chain vulnerabilities in compilers and standard libraries in recent years. We think it is important to include these in the SBOM to help with identifying and mitigating supply chain risks.

Dependencies that are not loaded at runtime have the `scope: excluded` field set in the CycloneDX BOM, making it easy to identify and filter them out (if needed).

## Kubernetes BOM generation

> This is an experimental feature and may be radically changed or removed in future releases.

The `k8s` command allows you to create an BOM (snapshot) of all the running resources, both control-plane and workloads, in a k8s cluster. It can optionally create SBOMs for all identified running images.

For creating the snapshot it uses [kubectl](https://kubernetes.io/docs/reference/kubectl/overview/).

Example: 

```
$ observer k8s --sbom --upload
``` 

Uploading these BOMs to a tool like [SBOM Observer](https://sbom.observer) allows you to identify vulnerabilities both in workloads and control-plane components, including advisories published to the [Kubernetes Official CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/).

## Uploading to SBOM Observer

To upload SBOMs to [SBOM Observer](https://sbom.observer) using the `upload` command, the CLI expects an `OBSERVER_TOKEN` environment variable to be set with a valid API token.

## Acknowledgements

This project is funded by the [National Coordination Centre for Research and Innovation in Cybersecurity (NCC-SE)](https://www.ncc-se.se/) and [The Swedish
Civil Contingencies Agency (MSB)](https://msb.se) with co-financing from the European Union.

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

