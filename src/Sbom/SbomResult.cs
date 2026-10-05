namespace Sbom;

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
