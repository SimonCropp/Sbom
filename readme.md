# <img src="/src/icon.png" height="30px"> Sbom

[![Build status](https://github.com/SimonCropp/Sbom/actions/workflows/build.yml/badge.svg)](https://github.com/SimonCropp/Sbom/actions/workflows/build.yml)
[![NuGet Status](https://img.shields.io/nuget/v/Sbom.svg)](https://www.nuget.org/packages/Sbom/)

Adds an [SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/) software bill of materials to every
NuGet package at pack time. A .NET-specific, drop-in replacement for
[Microsoft.Sbom.Targets](https://github.com/microsoft/sbom-tool).

**See [Milestones](../../milestones?state=closed) for release notes.**


## Why

Microsoft.Sbom.Targets runs sbom-tool, which runs every Component Detection detector (Maven, pip,
Ivy, npm, Go, Gradle, and more) over the project directory, then unzips and re-zips the package.
For a .NET package almost all of that is wasted. NuGet has already recorded the resolved
dependency graph in `obj/project.assets.json` (or `packages.lock.json`), and every dependency's license and authors sit in its
`.nuspec` in the local package cache.


### Benchmark

Packing a net10.0 library with 30 direct `PackageReference`s (179 packages once transitive dependencies are resolved). Median of 5 runs of `dotnet pack --no-build -m:1`, after one warm-up pack; restore and compile excluded.<!-- include: benchmark. path: /docs/benchmark.include.md -->

| | SBOM step | Whole pack | Peak memory of the pack process |
|---|--:|--:|--:|
| No SBOM | – | 663 ms | 110 MB |
| Microsoft.Sbom.Targets 4.1.13 | 1,368 ms | 2,041 ms | 198 MB |
| Sbom | 37 ms | 716 ms | 117 MB |

Sbom's SBOM step is 37x faster, and it adds 7 MB of peak memory to the pack where Microsoft.Sbom.Targets adds 89 MB.

Measured with SDK 10.0.401 on Microsoft Windows 10.0.28000, 16 logical cores, by `BenchmarkTests` in the integration tests.<!-- endInclude -->

Microsoft.Sbom.Targets' cost grows with the size of the project directory, because Component
Detection walks all of it and probes for Maven, pip and Ant. The fixture above sits alone in a
temp directory, so this is close to its best case; in a real repository the same step has been
measured at 16 seconds. Sbom's cost depends only on the restore graph and the package.

To rerun, after `dotnet build src -c Release` and `dotnet build IntegrationTests -c Release`:

```
dotnet run --project IntegrationTests/IntegrationTests -c Release --no-build -- --treenode-filter "/*/*/BenchmarkTests/*"
```


### Also


 * Offline. Nothing is fetched, so a flaky network cannot fail a pack.
 * Spec-conformant SPDX 3.0.1 that validates against the official JSON schema. sbom-tool's "3.0"
   output does not: it uses upper-case relationship types, relative ids and abstract element types.
 * Deterministic. Element ids and the document namespace are content hashes, and with
   `SOURCE_DATE_EPOCH` (or NuGet's `DeterministicTimestamp`) the same inputs produce the same bytes.
 * The package is written once, by NuGet. The manifest is handed to pack as one more package file,
   so nothing unzips, rewrites or re-zips the nupkg afterwards, and an unchanged SBOM leaves an
   up-to-date package alone.
 * Incremental. When neither the project files, the restore graph, nor any package property has
   changed, generation is skipped entirely, so a build that repacks through
   `GeneratePackageOnBuild` pays nothing for the SBOM.
 * Dependencies are marked as `runtime` or `build` (`PrivateAssets="all"`), including source-only
   packages compiled into the assembly.
 * Fast enough that `Condition="'$(CI)' == 'true'"` is no longer needed.


## Usage

Reference the package:

```xml
<PackageReference Include="Sbom" Version="x.y.z" PrivateAssets="all" />
```

`dotnet pack`, or a build with `GeneratePackageOnBuild`, then packs:

 * `_manifest/spdx_3.0/manifest.spdx.json`
 * `_manifest/spdx_3.0/manifest.spdx.json.sha256`: lowercase hex SHA-256 of the manifest, the same
   sidecar convention as sbom-tool.

The dependency graph comes from `packages.lock.json` when the project uses
[lock files](https://learn.microsoft.com/nuget/consume-packages/package-references-in-project-files#locking-dependencies),
otherwise from `obj/project.assets.json`, which restore always writes. Both hold the same resolved
graph. A lock file has the advantage of being committed, and restoring with `RestoreLockedMode` on
CI guarantees it matches what was built:

```xml
<RestoreLockedMode Condition="'$(CI)' == 'true'">true</RestoreLockedMode>
```


## Output

The document describes:

 * The package itself: id, version, supplier (from `Authors`), license, project URL, copyright,
   repository URL and commit, from the same pack properties NuGet writes into the nuspec.
 * Every resolved NuGet dependency, direct and transitive, across all
   target frameworks: purl (`pkg:nuget/Id@Version`), the NuGet content hash (SHA-512), supplier and
   declared license from its nuspec, and the dependency edges between packages.
 * Project references, as packages by name.
 * Direct dependencies grouped into `runtime` and `build` scoped relationships.

Framework references (`Microsoft.NETCore.App` and friends) and RID-specific runtime packages are
not listed.


## Settings

| Property | Default | |
|---|---|---|
| `SbomEnabled` | `true` | `false` skips generation. `GenerateSBOM=false` is also honoured. |
| `SbomSupplier` | the package's `Authors` | The supplier of the root package, and the SBOM's creator. |
| `SbomNamespaceBaseUri` | `https://spdx.org/spdxdocs/` | Prefix of the document namespace and every element id. |
| `NuGetLockFilePath` | `packages.lock.json` | NuGet's own setting; honoured. |


## Differences from Microsoft.Sbom.Targets

 * **Format.** SPDX 3.0.1 JSON-LD in `_manifest/spdx_3.0/`, where Microsoft.Sbom.Targets writes
   SPDX 2.2 to `_manifest/spdx_2.2/`.
 * **No per-file entries.** Microsoft.Sbom.Targets lists every file in the nupkg with its hashes.
   Sbom describes the package and its dependency graph, and lists no files:
   * Neither SPDX 3.0.1, nor the [NTIA minimum elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom),
     nor CISA's update to them asks for file entries. The hashes they ask for are per component,
     and every dependency carries NuGet's SHA-512 content hash.
   * File hashes stored inside the package they describe prove nothing about it: whoever can change
     a file can change the manifest too. The package signature and NuGet's content hash already
     cover every byte, manifest included.
   * Listing files would mean hashing the finished package, which is what forces
     Microsoft.Sbom.Targets to unzip and re-zip it after pack. Without them, the SBOM is complete
     before NuGet writes the package.
 * **Only NuGet dependencies.** The graph is NuGet's own restore graph. Component Detection also
   reports npm, pip, Maven and other ecosystems it finds anywhere under the project directory,
   whether or not they ship in the package.
 * **Build and runtime scopes.** Direct dependencies are split by `PrivateAssets="all"`, so
   analyzers and source-only packages are distinguishable from what a consumer receives.
 * **`NuspecFile` packs are not supported** ([Sbom010](/docs/DiagnosticCodes.md#sbom010)). NuGet then
   packs only the files the nuspec lists.


### Migrating

 * Replace the `Microsoft.Sbom.Targets` reference with `Sbom`.
 * `SbomGenerationPackageSupplier` becomes `SbomSupplier`, and `SbomGenerationNamespaceBaseUri`
   becomes `SbomNamespaceBaseUri`. Package name and version come from the pack properties. The other
   `SbomGeneration*` properties have no equivalent.
 * Drop any `Condition="'$(CI)' == 'true'"` on the reference.
 * While both are referenced, Microsoft.Sbom.Targets replaces the `_manifest` folder when it re-zips
   the package, so only its SBOM survives, and warning
   [Sbom006](/docs/DiagnosticCodes.md#sbom006) is raised.


## Signing

The manifest is packed with every other file, so signing the package afterwards covers it like any
other entry.


## Diagnostics

| Code | Meaning | Level |
|---|---|---|
| [Sbom001](/docs/DiagnosticCodes.md#sbom001) | Dependency graph unavailable | Error |
| [Sbom004](/docs/DiagnosticCodes.md#sbom004) | Dependency metadata unavailable | Message |
| [Sbom005](/docs/DiagnosticCodes.md#sbom005) | NuGet lock file may be stale | Warning |
| [Sbom006](/docs/DiagnosticCodes.md#sbom006) | Microsoft.Sbom.Targets also generates an SBOM | Warning |
| [Sbom008](/docs/DiagnosticCodes.md#sbom008) | SBOM generation failed | Error |
| [Sbom010](/docs/DiagnosticCodes.md#sbom010) | NuspecFile packs not supported | Warning |

Sbom002, Sbom003, Sbom007 and Sbom009 were retired in 0.3.0; see
[retired codes](/docs/DiagnosticCodes.md#retired-codes).
