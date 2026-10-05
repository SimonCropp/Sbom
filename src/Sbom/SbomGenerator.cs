namespace Sbom;

public sealed record ReferenceInfo(string Id, bool IsPrivate);

public sealed class SbomRequest
{
    public string ManifestFile { get; init; } = "";
    public string NuspecFile { get; init; } = "";
    public NuspecMetadata Root { get; init; } = new();
    public string LockFile { get; init; } = "";
    public string AssetsFile { get; init; } = "";
    public string PackageRoot { get; init; } = "";
    public IReadOnlyList<ReferenceInfo> References { get; init; } = [];
    public string? Supplier { get; init; }
    public string? NamespaceBaseUri { get; init; }
    public string? DeterministicTimestamp { get; init; }
    public string? SourceDateEpoch { get; init; }
    public bool MicrosoftSbomActive { get; init; }
    public string ToolVersion { get; init; } = "0.0.0";
    public Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;
}

public sealed class SbomResult
{
    public List<Diagnostic> Diagnostics { get; } = [];

    /// <summary>
    /// The manifest and its sidecar on disk, for NuGet to pack. Empty when there is no SBOM.
    /// </summary>
    public List<string> Files { get; } = [];

    /// <summary>
    /// False when the manifest on disk already had these exact bytes and was left alone.
    /// </summary>
    public bool Written { get; set; }

    public int Dependencies { get; set; }
    public long ElapsedMilliseconds { get; set; }
}

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
        var hasLockFile = request.LockFile.Length > 0 && File.Exists(request.LockFile);
        var hasAssetsFile = request.AssetsFile.Length > 0 && File.Exists(request.AssetsFile);
        if (!hasLockFile && !hasAssetsFile)
        {
            diagnostics.Add(
                new(
                    Diagnostics.LockFileMissing,
                    Severity.Error,
                    $"Neither '{request.LockFile}' nor '{request.AssetsFile}' exists, so the dependency graph is unknown. Restore the project before packing."));
            return result;
        }

        if (hasLockFile &&
            hasAssetsFile &&
            File.GetLastWriteTimeUtc(request.LockFile) < File.GetLastWriteTimeUtc(request.AssetsFile).AddSeconds(-2))
        {
            diagnostics.Add(
                new(
                    Diagnostics.LockFileStale,
                    Severity.Warning,
                    $"'{request.LockFile}' is older than the last restore. Restore with RestoreLockedMode on CI to guarantee the lock file matches what was built."));
        }

        var root = request.Root;
        if (root.Version != null)
        {
            root.Version = Versions.Normalize(root.Version);
        }

        var dependencies = BuildDependencies(request, hasLockFile, diagnostics);

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

    static List<SbomDependency> BuildDependencies(SbomRequest request, bool hasLockFile, List<Diagnostic> diagnostics)
    {
        List<LockedDependency> locked;
        if (hasLockFile)
        {
            locked = LockFile.Read(request.LockFile);
        }
        else
        {
            locked = AssetsFile.Read(request.AssetsFile);
        }

        // A direct reference is build-only when every PackageReference/ProjectReference item for it,
        // across every target framework, is PrivateAssets=all.
        var privacy = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var reference in request.References)
        {
            if (privacy.TryGetValue(reference.Id, out var existing))
            {
                privacy[reference.Id] = existing && reference.IsPrivate;
                continue;
            }

            privacy[reference.Id] = reference.IsPrivate;
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
