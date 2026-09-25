namespace Sbom;

public sealed class SbomDependency(string id, string? version, DependencyKind kind)
{
    public string Id { get; } = id;
    public string? Version { get; } = version;
    public DependencyKind Kind { get; } = kind;
    public string? ContentHashHex { get; set; }
    public bool IsDirect { get; set; }
    public bool IsBuildOnly { get; set; }
    public NuspecMetadata? Metadata { get; set; }

    /// <summary>
    /// Other dependencies, by <see cref="Key"/>.
    /// </summary>
    public List<string> DependsOn { get; } = [];

    public string Key => LockedDependency.MakeKey(Id, Version);
}

public sealed class SbomInput
{
    public required NuspecMetadata Root { get; init; }
    public string? Supplier { get; init; }
    public required IReadOnlyList<PackageFile> Files { get; init; }
    public required IReadOnlyList<SbomDependency> Dependencies { get; init; }
    public required DateTimeOffset Created { get; init; }
    public string? NamespaceBaseUri { get; init; }
    public required string ToolVersion { get; init; }
}
