namespace Sbom;

/// <summary>
/// Diagnostic codes, their short names, and the message shape every emitted finding shares.
/// </summary>
public static class Diagnostics
{
    public const string Subcategory = "Sbom";

    public const string LockFileMissing = "Sbom001";
    public const string PackageNotFound = "Sbom002";
    public const string PackageSigned = "Sbom003";
    public const string NuspecMissing = "Sbom004";
    public const string LockFileStale = "Sbom005";
    public const string MicrosoftSbomActive = "Sbom006";
    public const string UnsupportedLayout = "Sbom007";
    public const string Failed = "Sbom008";
    public const string AlreadyPresent = "Sbom009";

    public static readonly string[] All =
    [
        LockFileMissing,
        PackageNotFound,
        PackageSigned,
        NuspecMissing,
        LockFileStale,
        MicrosoftSbomActive,
        UnsupportedLayout,
        Failed,
        AlreadyPresent
    ];

    const string docsBaseUrl = "https://github.com/SimonCropp/Sbom/blob/main/docs/DiagnosticCodes.md";

    public static string NameFor(string code) =>
        code switch
        {
            LockFileMissing => "NuGet lock file missing",
            PackageNotFound => "Package not found",
            PackageSigned => "Package is signed",
            NuspecMissing => "Dependency metadata unavailable",
            LockFileStale => "NuGet lock file may be stale",
            MicrosoftSbomActive => "Microsoft.Sbom.Targets also generates an SBOM",
            UnsupportedLayout => "Package layout not supported",
            Failed => "SBOM generation failed",
            AlreadyPresent => "SBOM already present",
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
