namespace Sbom;

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
