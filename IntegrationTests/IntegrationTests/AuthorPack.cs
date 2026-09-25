using System.Text.Json;
using Json.Schema;

namespace Sbom.IntegrationTests;

public sealed record PackResult(CliResult Cli, string WorkDirectory, string? Nupkg)
{
    public byte[] Entry(string name)
    {
        using var archive = ZipFile.OpenRead(Nupkg!);
        using var buffer = new MemoryStream();
        using (var stream = archive.GetEntry(name)!.Open())
        {
            stream.CopyTo(buffer);
        }

        return buffer.ToArray();
    }

    public string Manifest => Encoding.UTF8.GetString(Entry("_manifest/spdx_3.0/manifest.spdx.json"));
}

/// <summary>
/// Copies a fixture to a temp directory, isolates it from this repository's props and targets, and
/// packs it against the Sbom package just built.
/// </summary>
public static class AuthorPack
{
    // One package folder per run: nuget.org packages download once, and the freshly built Sbom
    // cannot be shadowed by an older copy of the same version in the user's global cache.
    static readonly Lazy<string> packages = new(() =>
    {
        var path = Path.Combine(Path.GetTempPath(), "sbom-it-pkgs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    });

    public static async Task<PackResult> Pack(
        string fixture,
        string project,
        IReadOnlyDictionary<string, string>? properties = null,
        [CallerMemberName] string caller = "")
    {
        var work = TestEnvironment.MakeWorkDirectory(caller);
        TestEnvironment.CopyDirectory(Path.Combine(TestEnvironment.FixturesDirectory, fixture), work);
        TestEnvironment.WriteNugetConfig(work, PackageUnderTest.Ensure().Feed);
        File.WriteAllText(Path.Combine(work, "Directory.Build.props"), "<Project />");
        File.WriteAllText(Path.Combine(work, "Directory.Build.targets"), "<Project />");
        File.WriteAllText(Path.Combine(work, "Directory.Packages.props"), "<Project />");
        File.Copy(Path.Combine(TestEnvironment.RepoRoot, "IntegrationTests", "global.json"), Path.Combine(work, "global.json"));
        return await Repack(work, project, properties);
    }

    /// <summary>
    /// Packs again in an existing work directory, after removing the previous output so NuGet
    /// writes a fresh package.
    /// </summary>
    public static async Task<PackResult> Repack(
        string work,
        string project,
        IReadOnlyDictionary<string, string>? properties = null)
    {
        var package = PackageUnderTest.Ensure();

        var allProperties = new Dictionary<string, string>
        {
            ["SbomVersion"] = package.Version
        };
        if (properties != null)
        {
            foreach (var property in properties)
            {
                allProperties[property.Key] = property.Value;
            }
        }

        var output = Path.Combine(work, "out");
        if (Directory.Exists(output))
        {
            Directory.Delete(output, true);
        }

        var cli = await DotnetCliRunner.Run(
            "pack",
            Path.Combine(work, project),
            allProperties,
            workingDirectory: work,
            packagesDirectory: packages.Value,
            arguments: ["--configuration", "Release", "--output", output, "--disable-build-servers"]);

        string? nupkg = null;
        if (Directory.Exists(output))
        {
            nupkg = Directory.GetFiles(output, "*.nupkg").SingleOrDefault();
        }

        return new(cli, work, nupkg);
    }

    static readonly Lazy<JsonSchema> schema = new(() =>
        JsonSchema.FromFile(Path.Combine(AppContext.BaseDirectory, "Schemas", "spdx-json-schema-3.0.1.json")));

    public static bool IsValid(string manifest)
    {
        using var document = JsonDocument.Parse(manifest);
        return schema.Value.Evaluate(document.RootElement).IsValid;
    }
}
