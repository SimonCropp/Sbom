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
dependency graph in `packages.lock.json`, and every dependency's license and authors sit in its
`.nuspec` in the local package cache.


### Benchmark

Packing a net10.0 library with 30 direct `PackageReference`s (179 packages once transitive dependencies are resolved). Median of 5 runs of `dotnet pack --no-build -m:1`, after one warm-up pack; restore and compile excluded.<!-- include: benchmark. path: /docs/benchmark.include.md -->

| | SBOM step | Whole pack | Peak memory of the pack process |
|---|--:|--:|--:|
| No SBOM | – | 745 ms | 113 MB |
| Microsoft.Sbom.Targets 4.1.13 | 1,630 ms | 2,373 ms | 200 MB |
| Sbom | 48 ms | 780 ms | 117 MB |

Sbom's SBOM step is 34x faster, and it adds 5 MB of peak memory to the pack where Microsoft.Sbom.Targets adds 87 MB.

Measured with SDK 10.0.401 on Microsoft Windows 10.0.28000, 16 logical cores, by `BenchmarkTests` in the integration tests.<!-- endInclude -->

Microsoft.Sbom.Targets' cost grows with the size of the project directory, because Component
Detection walks all of it and probes for Maven, pip and Ant. The fixture above sits alone in a
temp directory, so this is close to its best case; in a real repository the same step has been
measured at 16 seconds. Sbom's cost depends only on the lock file and the package.

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
 * The package is not rewritten. The two manifest entries are appended, so every existing byte of
   the nupkg stays as NuGet wrote it.
 * Dependencies are marked as `runtime` or `build` (`PrivateAssets="all"`), including source-only
   packages compiled into the assembly.
 * Fast enough that `Condition="'$(CI)' == 'true'"` is no longer needed.


## Usage

Enable NuGet lock files and reference the package:

```xml
<PropertyGroup>
  <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
</PropertyGroup>
<ItemGroup>
  <PackageReference Include="Sbom" Version="x.y.z" PrivateAssets="all" />
</ItemGroup>
```

`dotnet pack`, or a build with `GeneratePackageOnBuild`, then adds:

 * `_manifest/spdx_3.0/manifest.spdx.json`
 * `_manifest/spdx_3.0/manifest.spdx.json.sha256`: lowercase hex SHA-256 of the manifest, the same
   sidecar convention as sbom-tool.

Restoring with `RestoreLockedMode` on CI guarantees the lock file matches what was built:

```xml
<RestoreLockedMode Condition="'$(CI)' == 'true'">true</RestoreLockedMode>
```


## Output

The document describes:

 * The package itself: id, version, supplier (from `Authors`), license, project URL, copyright,
   repository URL and commit, all read from the nuspec packed into the nupkg.
 * Every file in the nupkg, with its SHA-256.
 * Every resolved NuGet dependency from `packages.lock.json`, direct and transitive, across all
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


## Migrating from Microsoft.Sbom.Targets

 * Replace the `Microsoft.Sbom.Targets` reference with `Sbom` and enable
   `RestorePackagesWithLockFile`.
 * The manifest moves from `_manifest/spdx_2.2/` to `_manifest/spdx_3.0/`.
 * `SbomGenerationPackageSupplier` becomes `SbomSupplier`, and `SbomGenerationNamespaceBaseUri`
   becomes `SbomNamespaceBaseUri`. Package name and version come from the packed nuspec. The other
   `SbomGeneration*` properties have no equivalent.
 * While both are referenced, both SBOMs are written and warning [Sbom006](/docs/DiagnosticCodes.md#sbom006)
   is raised.


## Signing

Adding entries to a signed package would invalidate its signature, so a signed package is left
alone ([Sbom003](/docs/DiagnosticCodes.md#sbom003)). Sign after pack.


## Diagnostics

| Code | Meaning | Level |
|---|---|---|
| [Sbom001](/docs/DiagnosticCodes.md#sbom001) | NuGet lock file missing | Error |
| [Sbom002](/docs/DiagnosticCodes.md#sbom002) | Package not found | Warning |
| [Sbom003](/docs/DiagnosticCodes.md#sbom003) | Package is signed | Warning |
| [Sbom004](/docs/DiagnosticCodes.md#sbom004) | Dependency metadata unavailable | Message |
| [Sbom005](/docs/DiagnosticCodes.md#sbom005) | NuGet lock file may be stale | Warning |
| [Sbom006](/docs/DiagnosticCodes.md#sbom006) | Microsoft.Sbom.Targets also generates an SBOM | Warning |
| [Sbom007](/docs/DiagnosticCodes.md#sbom007) | Package layout not supported | Warning |
| [Sbom008](/docs/DiagnosticCodes.md#sbom008) | SBOM generation failed | Error |
| [Sbom009](/docs/DiagnosticCodes.md#sbom009) | SBOM already present | Message |
