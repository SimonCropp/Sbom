# Diagnostic codes

Every message Sbom emits carries a code, so any of them can be silenced per project:

```xml
<PropertyGroup>
  <NoWarn>$(NoWarn);Sbom006</NoWarn>
</PropertyGroup>
```


## Sbom001

**Dependency graph unavailable.** Error.

The dependency graph comes from `packages.lock.json` when the project has one, otherwise from
`obj/project.assets.json`, which restore always writes. Neither exists, so the project was not
restored. No SBOM is written, since an SBOM that silently lists no dependencies is worse than a
failed pack.

Fix: restore before packing (`dotnet pack` restores by default; `--no-restore` skips it).


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

Microsoft.Sbom.Targets is referenced and `GenerateSBOM` is `true`. It runs after pack, unzips the
package, replaces the `_manifest` folder with its own, and zips it again, so the package ends up with
only its SPDX 2.2 SBOM, and pack time is dominated by its component detection. Remove the
Microsoft.Sbom.Targets reference.


## Sbom008

**SBOM generation failed.** Error.

An unexpected failure, such as an unreadable lock file or an I/O error writing the manifest. The
message carries the exception. The build fails because it asked for an SBOM and did not get one.


## Sbom010

**NuspecFile packs not supported.** Warning.

The project sets `NuspecFile`, so NuGet packs the files listed in that nuspec and ignores the package
files MSBuild supplies, the SBOM among them. No SBOM is written. Pack from project properties
instead, or skip Sbom for this project with `SbomEnabled=false`.


## Retired codes

Sbom002 (package not found), Sbom003 (package is signed), Sbom007 (package layout not supported) and
Sbom009 (SBOM already present) were raised by versions before 0.3.0, which appended the SBOM to the
packed nupkg. Since 0.3.0 the SBOM is handed to NuGet as one more package file, so none of those
situations can arise. Codes are not reused.
