# Sbom

An MSBuild task package that appends an SPDX 3.0.1 SBOM to a nupkg after `Pack`. Dependencies come
from `packages.lock.json`; dependency metadata from each package's nuspec in `$(NuGetPackageRoot)`;
the root package's identity and metadata from the nuspec packed inside the nupkg.

## Layout

- `src/Sbom` - the task package. `netstandard2.0` only; `build/Sbom.targets` is packed to both
  `build/` and `buildMultiTargeting/`.
- `src/Sbom.Tests` - unit tests, including the SPDX golden vector and schema validation against the
  vendored official schema in `Schemas/`.
- `IntegrationTests/` - a separate solution that runs `dotnet pack` on fixtures against the nupkg the
  `src` Release build emits into `nugets/`, so `dotnet build src -c Release` must run first.

## Conventions

- `ProjectDefaults` supplies packaging metadata, nullable, implicit usings and code style. Never
  hand-edit `.editorconfig` or `Shared.sln.DotSettings`.
- One `NoWarn` property in `src/Directory.Build.props`.
- Tests are TUnit plus Verify, run with
  `dotnet run --project <project> -c Release --no-build -- --no-ansi --progress off`.
- No `return c ? a : b;` or `=> c ? a : b`: an `if` that returns, then the fallback return. No
  `else` after a branch that returns.

## Rules

- The task assembly stays `netstandard2.0`. A framework-specific asset selected on
  `$(MSBuildRuntimeType)` only loads on the newest SDK.
- Never use `ZipArchiveMode.Update`. It rewrites the whole archive on .NET Framework and .NET 8/9,
  and corrupts data-descriptor entries on .NET 10 (dotnet/runtime#126344). `NupkgWriter` appends
  raw bytes at the central directory offset.
- Output is a pure function of its inputs: ids and the namespace are content hashes, lists are
  ordinally sorted, newlines are `\n`, and no absolute path is ever written. The golden vector test
  (`u = 1a8ba6001e9e94bdc573fbefbbeea9a1`) pins the exact bytes.
- The output validates against the official SPDX 3.0.1 schema. Do not copy sbom-tool's "3.0"
  variant, which does not.
- Never touch the network, and never read `.nupkg.metadata` `source` (it would leak private feed
  URLs).
- Microsoft.Sbom.Targets deletes `_manifest/` when it re-zips, so when both are present it is run
  first through `CallTarget`.
- Adding or changing a diagnostic code means updating `docs/DiagnosticCodes.md` in the same change;
  a test checks every code has a section.
- `Sbom.targets` attributes on `SbomTask` must match the task's public properties; a test checks.
