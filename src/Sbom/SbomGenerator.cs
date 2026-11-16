namespace Sbom;

// ProjectPath: the full path of a ProjectReference, null for a PackageReference.
public sealed record ReferenceInfo(string Id, bool IsPrivate, string? ProjectPath = null);

public static class SbomGenerator
{
    public const string PackagePath = "_manifest/spdx_3.0/manifest.spdx.json";

    public static SbomResult Run(SbomRequest request)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new SbomResult();
        var diagnostics = result.Diagnostics;

        if (request.MicrosoftSbomActive)
        {
            diagnostics.Add(
                new(
                    Diagnostics.MicrosoftSbomActive,
                    Severity.Warning,
                    "Microsoft.Sbom.Targets is also referenced with GenerateSBOM=true. It re-zips the package after pack and replaces the _manifest folder, so this SBOM will not survive, and the slow one dominates pack time. Remove the Microsoft.Sbom.Targets reference."));
        }

        // A nuspec file lists its own files, and NuGet ignores every package file MSBuild supplies.
        if (request.NuspecFile.Trim().Length > 0)
        {
            diagnostics.Add(
                new(
                    Diagnostics.NuspecFileNotSupported,
                    Severity.Warning,
                    $"The package is packed from '{request.NuspecFile}', whose <files> NuGet uses instead of MSBuild's package files. No SBOM was written."));
            return result;
        }

        // The lock file is preferred: it is committed, and RestoreLockedMode can enforce it. Without
        // one, the assets file restore always writes holds the same resolved graph.
        var lockFile = request.LockFile;
        var hasLockFile = lockFile.Length > 0 && File.Exists(lockFile);
        var assetsFile = request.AssetsFile;
        var hasAssetsFile = assetsFile.Length > 0 && File.Exists(assetsFile);
        if (!hasLockFile && !hasAssetsFile)
        {
            diagnostics.Add(
                new(
                    Diagnostics.LockFileMissing,
                    Severity.Error,
                    $"Neither '{lockFile}' nor '{assetsFile}' exists, so the dependency graph is unknown. Restore the project before packing."));
            return result;
        }

        // Parsed at most once, and only when something needs it.
        AssetsContent? assets = null;
        AssetsContent Assets() => assets ??= AssetsFile.Read(assetsFile);

        List<LockedDependency> locked;
        if (hasLockFile)
        {
            locked = LockFile.Read(lockFile);
        }
        else
        {
            locked = Assets().Dependencies;
        }

        // Restore never rewrites a lock file whose content is unchanged, so one older than the
        // assets file is normal (a fresh clone, any locked-mode restore). Only a lock file not
        // written by the last restore can be newer, and only different packages make it stale.
        if (hasLockFile &&
            hasAssetsFile &&
            File.GetLastWriteTimeUtc(lockFile) < File.GetLastWriteTimeUtc(assetsFile).AddSeconds(-2) &&
            !SamePackages(locked, Assets().Dependencies))
        {
            diagnostics.Add(
                new(
                    Diagnostics.LockFileStale,
                    Severity.Warning,
                    $"'{lockFile}' lists different packages from '{assetsFile}', so the last restore did not use it. Restore with RestoreLockedMode on CI to guarantee the lock file matches what was built."));
        }

        var root = request.Root;
        if (root.Version != null)
        {
            root.Version = Versions.Normalize(root.Version);
        }

        var dependencies = BuildDependencies(request, locked, hasAssetsFile, Assets, diagnostics);

        var draft = SpdxBuilder.Draft(
            new()
            {
                Root = root,
                Supplier = Clean(request.Supplier),
                Dependencies = dependencies,
                NamespaceBaseUri = Clean(request.NamespaceBaseUri),
                ToolVersion = request.ToolVersion
            });

        var manifestFile = request.ManifestFile;
        var sidecarFile = manifestFile + ".sha256";
        byte[]? existing = null;
        if (File.Exists(manifestFile))
        {
            existing = File.ReadAllBytes(manifestFile);
        }

        var manifest = Finish(request, draft, existing);
        if (manifest != existing)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(manifestFile)!);
            File.WriteAllBytes(manifestFile, manifest);
            result.Written = true;
        }

        WriteIfChanged(sidecarFile, Encoding.ASCII.GetBytes(Hashing.Sha256Hex(manifest)));

        result.Files.Add(manifestFile);
        result.Files.Add(sidecarFile);
        result.Dependencies = dependencies.Count;
        result.ElapsedMilliseconds = stopwatch.ElapsedMilliseconds;
        return result;
    }

    /// <summary>
    /// Pack's up-to-date check compares the manifest's write time with the package's, so a manifest
    /// is only rewritten when it says something new. Left to the clock, "created" would differ on
    /// every pack; so when the previous manifest matches in everything else, its timestamp is kept.
    /// Returns <paramref name="existing"/> itself when it already has the right bytes.
    /// </summary>
    static byte[] Finish(SbomRequest request, SpdxDraft draft, byte[]? existing)
    {
        var requested = Timestamps.Explicit(request.DeterministicTimestamp, request.SourceDateEpoch);
        if (requested != null)
        {
            var manifest = SpdxBuilder.Finish(draft, requested.Value);
            if (existing != null &&
                Same(manifest, existing))
            {
                return existing;
            }

            return manifest;
        }

        // Creation info is the first element of the graph, so its timestamp is near the start.
        if (existing != null &&
            Timestamps.ReadCreated(Encoding.UTF8.GetString(existing, 0, Math.Min(existing.Length, 1024))) is { } previous)
        {
            var candidate = SpdxBuilder.Finish(draft, previous);
            if (Same(candidate, existing))
            {
                return existing;
            }
        }

        return SpdxBuilder.Finish(draft, Timestamps.Resolve(null, null, request.Now));
    }

    static void WriteIfChanged(string path, byte[] content)
    {
        if (File.Exists(path) &&
            Same(File.ReadAllBytes(path), content))
        {
            return;
        }

        File.WriteAllBytes(path, content);
    }

    /// <summary>
    /// A plain loop: on .NET Framework, Enumerable.SequenceEqual enumerates a byte[] one boxed
    /// comparison at a time.
    /// </summary>
    static bool Same(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        for (var index = 0; index < left.Length; index++)
        {
            if (left[index] != right[index])
            {
                return false;
            }
        }

        return true;
    }

    static bool SamePackages(List<LockedDependency> left, List<LockedDependency> right)
    {
        static HashSet<string> Packages(List<LockedDependency> dependencies) =>
            new(
                dependencies
                    .Where(_ => _.Kind == DependencyKind.Package)
                    .Select(_ => _.Key),
                StringComparer.Ordinal);

        return Packages(left).SetEquals(Packages(right));
    }

    static List<SbomDependency> BuildDependencies(
        SbomRequest request,
        List<LockedDependency> locked,
        bool hasAssetsFile,
        Func<AssetsContent> assets,
        List<Diagnostic> diagnostics)
    {
        // A direct reference is build-only when every PackageReference/ProjectReference item for it,
        // across every target framework, is PrivateAssets=all.
        var privacy = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var reference in request.References)
        {
            var id = ReferenceId(reference, hasAssetsFile, assets);
            if (privacy.TryGetValue(id, out var existing))
            {
                privacy[id] = existing && reference.IsPrivate;
                continue;
            }

            privacy[id] = reference.IsPrivate;
        }

        // Opening each nuspec dominates generation (file-open latency, not parsing), so they are read
        // concurrently. Results land by index, so output order does not depend on scheduling.
        var metadata = new NuspecMetadata?[locked.Count];
        Parallel.For(
            0,
            locked.Count,
            index =>
            {
                var entry = locked[index];
                if (entry is {Kind: DependencyKind.Package, Version: not null})
                {
                    metadata[index] = ReadMetadata(request.PackageRoot, entry.Id, entry.Version);
                }
            });

        var missing = new List<string>();
        var result = new List<SbomDependency>();
        for (var index = 0; index < locked.Count; index++)
        {
            var entry = locked[index];
            var dependency = new SbomDependency(entry.Id, entry.Version, entry.Kind)
            {
                ContentHashHex = entry.ContentHashHex,
                IsDirect = entry.IsDirect
            };
            dependency.DependsOn.AddRange(entry.DependsOn);
            if (entry.IsDirect &&
                privacy.TryGetValue(entry.Id, out var isPrivate))
            {
                dependency.IsBuildOnly = isPrivate;
            }

            if (entry is {Kind: DependencyKind.Package, Version: not null})
            {
                dependency.Metadata = metadata[index];
                if (dependency.Metadata == null)
                {
                    missing.Add($"{entry.Id} {entry.Version}");
                }
            }

            result.Add(dependency);
        }

        if (missing.Count > 0)
        {
            diagnostics.Add(
                new(
                    Diagnostics.NuspecMissing,
                    Severity.LowMessage,
                    $"No .nuspec in '{request.PackageRoot}' for: {string.Join(", ", missing)}. Those packages are listed without license or supplier."));
        }

        return result;
    }

    /// <summary>
    /// The lock and assets files name a project by its PackageId, which the reference's file name
    /// only matches by default. The assets file maps the project's path to that name.
    /// </summary>
    static string ReferenceId(ReferenceInfo reference, bool hasAssetsFile, Func<AssetsContent> assets)
    {
        if (reference.ProjectPath == null ||
            !hasAssetsFile)
        {
            return reference.Id;
        }

        if (assets().ProjectNames.TryGetValue(Path.GetFullPath(reference.ProjectPath), out var name))
        {
            return name;
        }

        return reference.Id;
    }

    static NuspecMetadata? ReadMetadata(string packageRoot, string id, string version)
    {
        if (packageRoot.Length == 0)
        {
            return null;
        }

        var lowerId = id.ToLowerInvariant();
        var path = Path.Combine(packageRoot, lowerId, version.ToLowerInvariant(), $"{lowerId}.nuspec");
        return NuspecMetadata.TryReadFile(path);
    }

    static string? Clean(string? value)
    {
        if (value == null)
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        return trimmed;
    }
}
