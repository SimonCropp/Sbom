namespace Sbom;

public sealed record ReferenceInfo(string Id, bool IsPrivate);

public sealed class SbomRequest
{
    public IReadOnlyList<string> PackOutputs { get; init; } = [];
    public string PackageOutputPath { get; init; } = "";
    public string PackageId { get; init; } = "";
    public string PackageVersion { get; init; } = "";
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
    public string? PackagePath { get; set; }
    public bool Written { get; set; }
    public int Files { get; set; }
    public int Dependencies { get; set; }
    public long ElapsedMilliseconds { get; set; }
}

public static class SbomGenerator
{
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
                    "Microsoft.Sbom.Targets is also referenced with GenerateSBOM=true. Both SBOMs are written, and the slow one dominates pack time. Remove the Microsoft.Sbom.Targets reference."));
        }

        var nupkg = PackageLocator.Find(request.PackOutputs, request.PackageOutputPath, request.PackageId, request.PackageVersion);
        if (nupkg == null)
        {
            diagnostics.Add(
                new(
                    Diagnostics.PackageNotFound,
                    Severity.Warning,
                    $"No .nupkg for {request.PackageId} {request.PackageVersion} was found in '{request.PackageOutputPath}'. No SBOM was written."));
            return result;
        }

        result.PackagePath = nupkg;

        var scan = NupkgReader.Scan(nupkg);
        if (scan.HasManifest)
        {
            diagnostics.Add(
                new(
                    Diagnostics.AlreadyPresent,
                    Severity.LowMessage,
                    $"'{nupkg}' already contains {NupkgReader.ManifestPath}; pack left the previous package in place."));
            return result;
        }

        if (scan.IsSigned)
        {
            diagnostics.Add(
                new(
                    Diagnostics.PackageSigned,
                    Severity.Warning,
                    $"'{nupkg}' is signed, and adding an SBOM would invalidate the signature. Sign after the SbomGenerate target instead."));
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

        var root = scan.Nuspec ?? new NuspecMetadata();
        root.Id ??= request.PackageId;
        root.Version ??= request.PackageVersion;

        var dependencies = BuildDependencies(request, hasLockFile, diagnostics);

        var input = new SbomInput
        {
            Root = root,
            Supplier = Clean(request.Supplier),
            Files = scan.Files,
            Dependencies = dependencies,
            Created = Timestamps.Resolve(request.DeterministicTimestamp, request.SourceDateEpoch, request.Now),
            NamespaceBaseUri = Clean(request.NamespaceBaseUri),
            ToolVersion = request.ToolVersion
        };

        var manifest = SpdxBuilder.Build(input);
        var sidecar = Encoding.ASCII.GetBytes(Hashing.Sha256Hex(manifest));
        NupkgWriter.Append(nupkg,
        [
            new(NupkgReader.ManifestPath, manifest),
            new(NupkgReader.ManifestHashPath, sidecar)
        ]);

        result.Written = true;
        result.Files = scan.Files.Count;
        result.Dependencies = dependencies.Count;
        result.ElapsedMilliseconds = stopwatch.ElapsedMilliseconds;
        return result;
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
