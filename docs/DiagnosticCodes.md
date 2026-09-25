# Diagnostic codes

Every message Sbom emits carries a code, so any of them can be silenced per project:

```xml
<PropertyGroup>
  <NoWarn>$(NoWarn);Sbom006</NoWarn>
</PropertyGroup>
```


## Sbom001

**NuGet lock file missing.** Error.

The dependency graph comes from `packages.lock.json`, and the project has none. No SBOM is written,
since an SBOM that silently lists no dependencies is worse than a failed pack.

Fix: enable lock files, then restore.

```xml
<PropertyGroup>
  <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
</PropertyGroup>
```

A custom location set through `NuGetLockFilePath` is honoured.


## Sbom002

**Package not found.** Warning.

Pack ran, but no `.nupkg` could be found in `@(NuGetPackOutput)` or in the package output directory
under `{PackageId}.{PackageVersion}.nupkg`, its normalized form, or `{PackageId}.nupkg`. No SBOM is
written.


## Sbom003

**Package is signed.** Warning.

The package already contains `.signature.p7s`. Adding entries would invalidate the signature, so no
SBOM is written. Sign in a target that runs after `SbomGenerate`, or after pack completes.


## Sbom004

**Dependency metadata unavailable.** Low-importance message.

A locked package has no `.nuspec` in the NuGet global packages folder, usually because restore ran
against a different folder. Those packages are listed without supplier, license, or homepage.


## Sbom005

**NuGet lock file may be stale.** Warning.

`packages.lock.json` is older than `project.assets.json`, so the last restore may not have written
it. The SBOM describes the lock file. Restoring with `RestoreLockedMode` on CI guarantees the two
match:

```xml
<PropertyGroup>
  <RestoreLockedMode Condition="'$(CI)' == 'true'">true</RestoreLockedMode>
</PropertyGroup>
```


## Sbom006

**Microsoft.Sbom.Targets also generates an SBOM.** Warning.

Microsoft.Sbom.Targets is referenced and `GenerateSBOM` is `true`. Both SBOMs are written: its
target runs first, since it deletes any existing `_manifest` folder when it re-zips the package.
Pack time is still dominated by its component detection. Remove the Microsoft.Sbom.Targets
reference.


## Sbom007

**Package layout not supported.** Warning.

The package uses ZIP64, spans disks, or has data between its central directory and end record. NuGet
does not produce any of these for packages under 4 GB. No SBOM is written.


## Sbom008

**SBOM generation failed.** Error.

An unexpected failure, such as a corrupt package or an I/O error. The message carries the exception.
The build fails because it asked for an SBOM and did not get one.


## Sbom009

**SBOM already present.** Low-importance message.

The package already contains `_manifest/spdx_3.0/manifest.spdx.json`. This happens on an
incremental build, where NuGet skips `GenerateNuspec` because nothing changed and the previous
package, SBOM included, stays in place.
