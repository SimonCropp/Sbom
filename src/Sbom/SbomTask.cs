using Task = Microsoft.Build.Utilities.Task;

/// <summary>
/// Appends an SPDX 3.0.1 SBOM to the package NuGet just packed. In the global namespace so
/// Sbom.targets can name it unqualified.
/// </summary>
public class SbomTask : Task
{
    public ITaskItem[] PackOutputs { get; set; } = [];
    public string PackageOutputPath { get; set; } = "";
    public string PackageId { get; set; } = "";
    public string PackageVersion { get; set; } = "";
    public string LockFile { get; set; } = "";
    public string AssetsFile { get; set; } = "";
    public string PackageRoot { get; set; } = "";
    public ITaskItem[] References { get; set; } = [];
    public string Supplier { get; set; } = "";
    public string NamespaceBaseUri { get; set; } = "";
    public string DeterministicTimestamp { get; set; } = "";
    public string SourceDateEpoch { get; set; } = "";
    public string MicrosoftSbomActive { get; set; } = "";

    public override bool Execute()
    {
        try
        {
            var request = new SbomRequest
            {
                PackOutputs = PackOutputs.Select(_ => _.GetMetadata("FullPath")).ToList(),
                PackageOutputPath = PackageOutputPath,
                PackageId = PackageId,
                PackageVersion = PackageVersion,
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

            if (result.Written)
            {
                Log.LogMessage(
                    MessageImportance.Normal,
                    $"Sbom: added {NupkgReader.ManifestPath} to '{result.PackagePath}' ({result.Files} files, {result.Dependencies} dependencies) in {result.ElapsedMilliseconds} ms.");
            }
        }
        catch (UnsupportedArchiveException exception)
        {
            Report(new(Diagnostics.UnsupportedLayout, Severity.Warning, $"{exception.Message} No SBOM was written."));
        }
        catch (Exception exception)
        {
            Report(new(Diagnostics.Failed, Severity.Error, exception.ToString()));
        }

        return !Log.HasLoggedErrors;
    }

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
