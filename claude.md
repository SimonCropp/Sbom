# Sbom

An MSBuild task package that writes an SPDX 3.0.1 SBOM to `obj/` just before `GenerateNuspec`, and
hands it to NuGet as one more package file, so NuGet packs it. Dependencies come from
`packages.lock.json`, or `obj/project.assets.json` when there is no lock file; dependency metadata
from each package's nuspec in `$(NuGetPackageRoot)`; the root package's identity and metadata from
the same pack properties NuGet writes into the nuspec.

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
- Never open or modify the packed nupkg. The SBOM lists no files, which is what lets it be complete
  before pack; do not add file entries back.
- `SbomGenerate` is `BeforeTargets="GenerateNuspec"`, not in `GenerateNuspecDependsOn`: dependencies
  run before any BeforeTargets, and ProjectDefaults sets `Authors` and the license in its own
  `BeforeTargets="GenerateNuspec"` target, imported earlier.
- The per-framework `MSBuild` call must use exactly the global properties the build already used
  (`TargetFramework` alone when multi-targeted, none when single-targeted). Any other set
  re-evaluates the project, 100+ ms per framework.
- The manifest is rewritten only when its content changes, keeping the previous `created` when the
  timestamp is left to the clock; otherwise every pack would be out of date.
- `SbomGenerate` is incremental. Its inputs are the project files, the lock and assets files, the
  task assembly, and `inputs.txt`, which records every property passed to `SbomTask`; its output is
  `sbom.stamp`, not the manifest, which keeps its old write time when unchanged. A new task
  property goes into `inputs.txt` too; a test checks.
- Output is a pure function of its inputs: ids and the namespace are content hashes, lists are
  ordinally sorted, newlines are `\n`, and no absolute path is ever written. The golden vector test
  (`u = 8fbdb3b144b7f806d6edf18901df4826`) pins the exact bytes.
- The output validates against the official SPDX 3.0.1 schema. Do not copy sbom-tool's "3.0"
  variant, which does not.
- Never touch the network, and never read `.nupkg.metadata` `source` (it would leak private feed
  URLs).
- Microsoft.Sbom.Targets replaces `_manifest/` when it re-zips after pack, so with both present only
  its SBOM survives; Sbom006 says so.
- Diagnostic codes are never reused. Retired codes stay listed under "Retired codes" in
  `docs/DiagnosticCodes.md`.
- Adding or changing a diagnostic code means updating `docs/DiagnosticCodes.md` in the same change;
  a test checks every code has a section.
- `Sbom.targets` attributes on `SbomTask` must match the task's public properties; a test checks.
