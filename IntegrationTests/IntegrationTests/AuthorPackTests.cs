public class AuthorPackTests
{
    [Test]
    public async Task Basic()
    {
        var result = await AuthorPack.Pack("Author.Basic", "Author.Basic.csproj");
        await Assert.That(result.Cli.ExitCode).IsEqualTo(0).Because(result.Cli.Combined);

        var manifest = result.Entry("_manifest/spdx_3.0/manifest.spdx.json");
        var sidecar = Encoding.ASCII.GetString(result.Entry("_manifest/spdx_3.0/manifest.spdx.json.sha256"));
        await Assert.That(sidecar).IsEqualTo(Convert.ToHexStringLower(SHA256.HashData(manifest)));

        var json = result.Manifest;
        await Assert.That(AuthorPack.IsValid(json)).IsTrue();
        await Assert.That(json).DoesNotContain(result.WorkDirectory.Replace("\\", "\\\\"));
        await Assert.That(json).DoesNotContain(Path.GetTempPath().Replace("\\", "\\\\"));

        var graph = Graph(json);
        await Assert.That(Scoped(graph, "runtime")).Contains("pkg:nuget/Newtonsoft.Json@13.0.3");
        await Assert.That(Scoped(graph, "build")).Contains("pkg:nuget/JetBrains.Annotations@2026.2.0");
        await Assert.That(Scoped(graph, "build")).Contains($"pkg:nuget/Sbom@{PackageUnderTest.Ensure().Version}");

        // Root identity and metadata come from the pack properties, and match the packed nuspec.
        var root = graph.Single(_ => _.TryGetProperty("software_primaryPurpose", out _));
        await Assert.That(root.GetProperty("software_packageUrl").GetString()).IsEqualTo("pkg:nuget/Author.Basic@1.0.0");
        await Assert.That(json).Contains("\"name\": \"Acme\"");
        await Assert.That(graph.Any(_ => _.GetProperty("type").GetString() == "software_File")).IsFalse();
    }

    [Test]
    public async Task IncrementalPackLeavesThePackageAlone()
    {
        var first = await AuthorPack.Pack("Author.Basic", "Author.Basic.csproj");
        await Assert.That(first.Cli.ExitCode).IsEqualTo(0).Because(first.Cli.Combined);
        var written = File.GetLastWriteTimeUtc(first.Nupkg!);
        var bytes = await File.ReadAllBytesAsync(first.Nupkg!);
        var stamp = Path.Combine(first.WorkDirectory, "obj", "Release", "sbom", "sbom.stamp");
        var stamped = File.GetLastWriteTimeUtc(stamp);

        var second = await AuthorPack.Repack(first.WorkDirectory, "Author.Basic.csproj", clean: false);
        await Assert.That(second.Cli.ExitCode).IsEqualTo(0).Because(second.Cli.Combined);
        // No input changed, so SbomGenerate is skipped, the manifest is untouched, GenerateNuspec
        // stays up to date and the package is not written again.
        await Assert.That(File.GetLastWriteTimeUtc(stamp)).IsEqualTo(stamped);
        await Assert.That(File.GetLastWriteTimeUtc(second.Nupkg!)).IsEqualTo(written);
        await Assert.That((await File.ReadAllBytesAsync(second.Nupkg!)).SequenceEqual(bytes)).IsTrue();
    }

    [Test]
    public async Task ChangedPropertyRegenerates()
    {
        var first = await AuthorPack.Pack("Author.Basic", "Author.Basic.csproj");
        await Assert.That(first.Cli.ExitCode).IsEqualTo(0).Because(first.Cli.Combined);

        // Only a global property changes, no file; the recorded inputs still see it.
        var second = await AuthorPack.Repack(
            first.WorkDirectory,
            "Author.Basic.csproj",
            new Dictionary<string, string>
            {
                ["Version"] = "2.0.0"
            });
        await Assert.That(second.Cli.ExitCode).IsEqualTo(0).Because(second.Cli.Combined);
        await Assert.That(second.Manifest).Contains("pkg:nuget/Author.Basic@2.0.0");
        await Assert.That(second.Manifest).DoesNotContain("pkg:nuget/Author.Basic@1.0.0");
    }

    [Test]
    public async Task NuspecFileWarns()
    {
        var result = await AuthorPack.Pack("Author.NuspecFile", "Author.NuspecFile.csproj");
        await Assert.That(result.Cli.ExitCode).IsEqualTo(0).Because(result.Cli.Combined);
        await Assert.That(result.Cli.Combined).Contains("Sbom010");
        await using var archive = await ZipFile.OpenReadAsync(result.Nupkg!);
        await Assert.That(archive.Entries.Any(_ => _.FullName.StartsWith("_manifest/", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task SymbolPackageHasNoSbom()
    {
        var result = await AuthorPack.Pack(
            "Author.Basic",
            "Author.Basic.csproj",
            new Dictionary<string, string>
            {
                ["IncludeSymbols"] = "true",
                ["SymbolPackageFormat"] = "snupkg"
            });
        await Assert.That(result.Cli.ExitCode).IsEqualTo(0).Because(result.Cli.Combined);
        await Assert.That(result.Entry("_manifest/spdx_3.0/manifest.spdx.json").Length).IsGreaterThan(0);
        var symbols = Directory.GetFiles(Path.GetDirectoryName(result.Nupkg!)!, "*.snupkg").Single();
        await using var archive = await ZipFile.OpenReadAsync(symbols);
        await Assert.That(archive.Entries.Any(_ => _.FullName.StartsWith("_manifest/", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task MultiTargeted()
    {
        var result = await AuthorPack.Pack("Author.MultiTargeted", Path.Combine("App", "App.csproj"));
        await Assert.That(result.Cli.ExitCode).IsEqualTo(0).Because(result.Cli.Combined);
        var json = result.Manifest;
        await Assert.That(AuthorPack.IsValid(json)).IsTrue();

        var runtime = Scoped(Graph(json), "runtime");
        // Only referenced for netstandard2.0, so only visible from that framework's inner build.
        await Assert.That(runtime).Contains("pkg:nuget/System.Memory@4.6.3");
        await Assert.That(runtime).Contains("pkg:nuget/lib");
    }

    [Test]
    public async Task SourceDateEpochMakesTheManifestReproducible()
    {
        var properties = new Dictionary<string, string>
        {
            ["SOURCE_DATE_EPOCH"] = "1767225600"
        };
        var first = await AuthorPack.Pack("Author.Basic", "Author.Basic.csproj", properties);
        await Assert.That(first.Cli.ExitCode).IsEqualTo(0).Because(first.Cli.Combined);
        var firstManifest = first.Manifest;
        // Same directory, so the compiled assembly is identical and only Sbom's output is compared.
        var second = await AuthorPack.Repack(first.WorkDirectory, "Author.Basic.csproj", properties);
        await Assert.That(second.Cli.ExitCode).IsEqualTo(0).Because(second.Cli.Combined);
        await Assert.That(second.Manifest).IsEqualTo(firstManifest);
        await Assert.That(firstManifest).Contains("\"created\": \"2026-01-01T00:00:00Z\"");
    }

    [Test]
    public async Task Disabled()
    {
        var result = await AuthorPack.Pack(
            "Author.Basic",
            "Author.Basic.csproj",
            new Dictionary<string, string>
            {
                ["SbomEnabled"] = "false"
            });
        await Assert.That(result.Cli.ExitCode).IsEqualTo(0).Because(result.Cli.Combined);
        await using var archive = await ZipFile.OpenReadAsync(result.Nupkg!);
        await Assert.That(archive.Entries.Any(_ => _.FullName.StartsWith("_manifest/", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task NoLockFileUsesTheAssetsFile()
    {
        var result = await AuthorPack.Pack("Author.NoLockFile", "Author.NoLockFile.csproj");
        await Assert.That(result.Cli.ExitCode).IsEqualTo(0).Because(result.Cli.Combined);
        var json = result.Manifest;
        await Assert.That(AuthorPack.IsValid(json)).IsTrue();
        await Assert.That(Scoped(Graph(json), "runtime")).Contains("pkg:nuget/Newtonsoft.Json@13.0.3");
    }

    [Test]
    public async Task PackageShape()
    {
        await using var archive = await ZipFile.OpenReadAsync(PackageUnderTest.Ensure().NupkgPath);
        var entries = archive.Entries
            .Select(_ => _.FullName)
            .Where(_ => !_.StartsWith("_rels/", StringComparison.Ordinal) &&
                        !_.StartsWith("package/", StringComparison.Ordinal) &&
                        !_.StartsWith("_manifest/", StringComparison.Ordinal) &&
                        _ != "[Content_Types].xml")
            .OrderBy(_ => _, StringComparer.Ordinal)
            .ToList();

        await Assert.That(entries.Any(_ => _.StartsWith("lib/", StringComparison.Ordinal))).IsFalse();
        await Assert.That(entries.Any(_ => _.Contains("//", StringComparison.Ordinal))).IsFalse();
        await Assert.That(entries).Contains("tasks/netstandard2.0/Sbom.dll");
        // No dependencies: the task is one assembly, so nothing can conflict with what MSBuild loads.
        await Assert.That(entries.Where(_ => _.StartsWith("tasks/", StringComparison.Ordinal)))
            .IsEquivalentTo(["tasks/netstandard2.0/Sbom.dll"]);
        await Assert.That(entries).Contains("build/Sbom.targets");
        await Assert.That(entries).Contains("buildMultiTargeting/Sbom.targets");
    }

    static List<JsonElement> Graph(string json) =>
        JsonDocument.Parse(json).RootElement.GetProperty("@graph").EnumerateArray().ToList();

    /// <summary>
    /// The purls of the root package's direct dependencies in the given lifecycle scope.
    /// </summary>
    static List<string> Scoped(List<JsonElement> graph, string scope)
    {
        var purls = graph
            .Where(_ => _.GetProperty("type").GetString() == "software_Package")
            .ToDictionary(
                _ => _.GetProperty("spdxId").GetString()!,
                _ => _.GetProperty("software_packageUrl").GetString()!);
        return graph
            .Where(_ => _.TryGetProperty("scope", out var value) && value.GetString() == scope)
            .SelectMany(_ => _.GetProperty("to").EnumerateArray())
            .Select(_ => purls[_.GetString()!])
            .ToList();
    }
}
