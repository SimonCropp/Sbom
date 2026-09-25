using Task = Microsoft.Build.Utilities.Task;
using TaskItem = Microsoft.Build.Utilities.TaskItem;

/// <summary>
/// Writes an SPDX 3.0.1 SBOM for the package about to be packed, and returns it as package files
/// for NuGet to include. In the global namespace so Sbom.targets can name it unqualified.
/// </summary>
public class SbomTask : Task
{
    public string ManifestFile { get; set; } = "";
    public string NuspecFile { get; set; } = "";
    public string PackageId { get; set; } = "";
    public string PackageVersion { get; set; } = "";
    public string Authors { get; set; } = "";
    public string PackageLicenseExpression { get; set; } = "";
    public string PackageLicenseUrl { get; set; } = "";
    public string PackageProjectUrl { get; set; } = "";
    public string Copyright { get; set; } = "";
    public string RepositoryUrl { get; set; } = "";
    public string RepositoryCommit { get; set; } = "";
    public string PackageType { get; set; } = "";
    public string LockFile { get; set; } = "";
    public string AssetsFile { get; set; } = "";
    public string PackageRoot { get; set; } = "";
    public ITaskItem[] References { get; set; } = [];
    public string Supplier { get; set; } = "";
    public string NamespaceBaseUri { get; set; } = "";
    public string DeterministicTimestamp { get; set; } = "";
    public string SourceDateEpoch { get; set; } = "";
    public string MicrosoftSbomActive { get; set; } = "";

    /// <summary>
    /// The manifest and its sidecar, with PackagePath set, when there is an SBOM to pack.
    /// </summary>
    [Output]
    public ITaskItem[] PackageFiles { get; set; } = [];

    public override bool Execute()
    {
        try
        {
            var request = new SbomRequest
            {
                ManifestFile = ManifestFile,
                NuspecFile = NuspecFile,
                Root = Root(),
                LockFile = LockFile,
                AssetsFile = AssetsFile,
                PackageRoot = PackageRoot,
                References = References
                    .Select(_ => new ReferenceInfo(_.ItemSpec, IsPrivate(_.GetMetadata("PrivateAssets"))))
                    .ToList(),
                Supplier = Supplier,
                NamespaceBaseUri = NamespaceBaseUri,
                DeterministicTimestamp = DeterministicTimestamp,
                SourceDateEpoch = SourceDateEpoch,
                MicrosoftSbomActive = Flag(MicrosoftSbomActive),
                ToolVersion = ToolVersion()
            };

            var result = SbomGenerator.Run(request);
            foreach (var diagnostic in result.Diagnostics)
            {
                Report(diagnostic);
            }

            if (result.Files.Count == 0)
            {
                return !Log.HasLoggedErrors;
            }

            PackageFiles = result.Files
                .Select(_ => (ITaskItem)new TaskItem(
                    _,
                    new Dictionary<string, string>
                    {
                        ["PackagePath"] = SbomGenerator.PackageDirectory
                    }))
                .ToArray();
            var state = "unchanged";
            if (result.Written)
            {
                state = "written";
            }

            Log.LogMessage(
                MessageImportance.Normal,
                $"Sbom: {SbomGenerator.PackagePath} {state} ({result.Dependencies} dependencies) in {result.ElapsedMilliseconds} ms.");
        }
        catch (Exception exception)
        {
            Report(new(Diagnostics.Failed, Severity.Error, exception.ToString()));
        }

        return !Log.HasLoggedErrors;
    }

    NuspecMetadata Root() =>
        new()
        {
            Id = Clean(PackageId),
            Version = Clean(PackageVersion),
            Authors = Clean(Authors),
            // The same fallback NuGet's nuspec reader applies: a licenses.nuget.org URL is an
            // expression. A license file has no expression.
            LicenseExpression = Clean(PackageLicenseExpression) ?? NuspecMetadata.FromLicenseUrl(Clean(PackageLicenseUrl)),
            ProjectUrl = Clean(PackageProjectUrl),
            Copyright = Clean(Copyright),
            RepositoryUrl = Clean(RepositoryUrl),
            RepositoryCommit = Clean(RepositoryCommit),
            IsTool = PackageType
                .Split(';')
                .Any(_ => string.Equals(_.Split(',')[0].Trim(), "DotnetTool", StringComparison.OrdinalIgnoreCase))
        };

    void Report(Diagnostic diagnostic)
    {
        var message = Diagnostics.Render(diagnostic.Code, diagnostic.Body);
        switch (diagnostic.Severity)
        {
            case Severity.Error:
                Log.LogError(Diagnostics.Subcategory, diagnostic.Code, null, null, 0, 0, 0, 0, message);
                return;
            case Severity.Warning:
                Log.LogWarning(Diagnostics.Subcategory, diagnostic.Code, null, null, 0, 0, 0, 0, message);
                return;
            case Severity.Message:
                Log.LogMessage(Diagnostics.Subcategory, diagnostic.Code, null, null, 0, 0, 0, 0, MessageImportance.Normal, message);
                return;
            default:
                Log.LogMessage(Diagnostics.Subcategory, diagnostic.Code, null, null, 0, 0, 0, 0, MessageImportance.Low, message);
                return;
        }
    }

    static string? Clean(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        return trimmed;
    }

    static bool IsPrivate(string privateAssets) =>
        privateAssets
            .Split(';')
            .Any(_ => string.Equals(_.Trim(), "all", StringComparison.OrdinalIgnoreCase));

    static bool Flag(string value) =>
        string.Equals(value.Trim(), "true", StringComparison.OrdinalIgnoreCase);

    static string ToolVersion()
    {
        var version = typeof(SbomTask).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;
        if (version == null)
        {
            return "0.0.0";
        }

        var plus = version.IndexOf('+');
        if (plus >= 0)
        {
            return version.Substring(0, plus);
        }

        return version;
    }
}
