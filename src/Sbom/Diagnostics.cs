namespace Sbom;

/// <summary>
/// Diagnostic codes, their short names, and the message shape every emitted finding shares.
/// </summary>
public static class Diagnostics
{
    public const string Subcategory = "Sbom";

    // Sbom002, Sbom003, Sbom007 and Sbom009 were retired in 0.3.0, when the SBOM stopped being
    // appended to the packed nupkg. Codes are never reused.
    public const string LockFileMissing = "Sbom001";
    public const string NuspecMissing = "Sbom004";
    public const string LockFileStale = "Sbom005";
    public const string MicrosoftSbomActive = "Sbom006";
    public const string Failed = "Sbom008";
    public const string NuspecFileNotSupported = "Sbom010";

    public static readonly string[] All =
    [
        LockFileMissing,
        NuspecMissing,
        LockFileStale,
        MicrosoftSbomActive,
        Failed,
        NuspecFileNotSupported
    ];

    const string docsBaseUrl = "https://github.com/SimonCropp/Sbom/blob/main/docs/DiagnosticCodes.md";

    public static string NameFor(string code) =>
        code switch
        {
            LockFileMissing => "Dependency graph unavailable",
            NuspecMissing => "Dependency metadata unavailable",
            LockFileStale => "NuGet lock file may be stale",
            MicrosoftSbomActive => "Microsoft.Sbom.Targets also generates an SBOM",
            Failed => "SBOM generation failed",
            NuspecFileNotSupported => "NuspecFile packs not supported",
            _ => code
        };

    public static string DocsUrl(string code) =>
        $"{docsBaseUrl}#{code.ToLowerInvariant()}";

    public static string Render(string code, string body) =>
        $"{NameFor(code)}. {body} See: {DocsUrl(code)}";
}

public enum Severity
{
    Error,
    Warning,
    Message,
    LowMessage
}

public sealed record Diagnostic(string Code, Severity Severity, string Body);
