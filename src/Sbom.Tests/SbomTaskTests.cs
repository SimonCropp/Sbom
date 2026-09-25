public class SbomTaskTests
{
    const string lockFile =
        """
        {
          "version": 2,
          "dependencies": {
            "net10.0": {
              "Dep": {
                "type": "Direct",
                "requested": "[2.0.0, )",
                "resolved": "2.0.0",
                "contentHash": "AAEC",
                "dependencies": {
                  "Inner": "1.0.0"
                }
              },
              "Inner": {
                "type": "Transitive",
                "resolved": "1.0.0"
              },
              "Analyzer": {
                "type": "Direct",
                "requested": "[1.0.0, )",
                "resolved": "1.0.0"
              }
            }
          }
        }
        """;

    sealed class Setup : IDisposable
    {
        public TempDirectory Temp { get; } = new();
        public string Package { get; }
        public string LockFile { get; }
        public string PackageRoot { get; }

        public Setup(bool signed = false, bool withLockFile = true)
        {
            Package = Temp.Combine("out", "A.1.0.0.nupkg");
            Directory.CreateDirectory(Temp.Combine("out"));
            TestPackage.Create(
                Package,
                "A",
                "1.0.0",
                """<authors>Acme</authors><license type="expression">MIT</license>""",
                signed);
            LockFile = Temp.Combine("packages.lock.json");
            if (withLockFile)
            {
                File.WriteAllText(LockFile, lockFile);
            }

            PackageRoot = Temp.Combine("packages");
            Temp.Write("packages/dep/2.0.0/dep.nuspec",
                TestPackage.Nuspec("Dep", "2.0.0", """<authors>Dep Author</authors><license type="expression">Apache-2.0</license>"""));
        }

        public (SbomTask Task, StubBuildEngine Engine) Task()
        {
            var engine = new StubBuildEngine();
            var task = new SbomTask
            {
                BuildEngine = engine,
                PackOutputs = [new TaskItem(Package)],
                PackageId = "A",
                PackageVersion = "1.0.0",
                LockFile = LockFile,
                PackageRoot = PackageRoot + Path.DirectorySeparatorChar,
                References =
                [
                    new TaskItem("Dep"),
                    new TaskItem("Analyzer", new Dictionary<string, string> { ["PrivateAssets"] = "All" })
                ],
                SourceDateEpoch = "1767225600"
            };
            return (task, engine);
        }

        public void Dispose() => Temp.Dispose();
    }

    [Test]
    public async Task WritesAValidSbom()
    {
        using var setup = new Setup();
        var (task, engine) = setup.Task();

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings).IsEmpty();

        await using var archive = await ZipFile.OpenReadAsync(setup.Package);
        var manifest = Read(archive, NupkgReader.ManifestPath);
        var sidecar = Encoding.ASCII.GetString(Read(archive, NupkgReader.ManifestHashPath));
        await Assert.That(sidecar).IsEqualTo(Hashing.Sha256Hex(manifest));
        await Assert.That(SpdxBuilderTests.SchemaErrors(manifest)).IsEmpty();

        var json = Encoding.UTF8.GetString(manifest);
        await Assert.That(json).DoesNotContain(setup.Temp.Path.Replace("\\", "\\\\"));
        await Assert.That(json).Contains("\"name\": \"Dep Author\"");
        await Assert.That(json).Contains("\"simplelicensing_licenseExpression\": \"Apache-2.0\"");
        await Assert.That(json).Contains("\"created\": \"2026-01-01T00:00:00Z\"");
        await Assert.That(Scoped(json, "build")).IsEqualTo(1);
        await Assert.That(Scoped(json, "runtime")).IsEqualTo(1);
    }

    [Test]
    public async Task SecondRunLeavesThePackageAlone()
    {
        using var setup = new Setup();
        await Assert.That(setup.Task().Task.Execute()).IsTrue();
        var first = await File.ReadAllBytesAsync(setup.Package);

        var (task, engine) = setup.Task();
        await Assert.That(task.Execute()).IsTrue();
        await Assert.That((await File.ReadAllBytesAsync(setup.Package)).SequenceEqual(first)).IsTrue();
        await Assert.That(engine.Messages.Any(_ => _.Code == Diagnostics.AlreadyPresent)).IsTrue();
    }

    [Test]
    public async Task SameInputsSameBytes()
    {
        using var one = new Setup();
        using var two = new Setup();
        one.Task().Task.Execute();
        var (task, _) = two.Task();
        task.PackageRoot = one.PackageRoot;
        task.Execute();

        await using var a = await ZipFile.OpenReadAsync(one.Package);
        await using var b = await ZipFile.OpenReadAsync(two.Package);
        await Assert.That(Read(a, NupkgReader.ManifestPath).SequenceEqual(Read(b, NupkgReader.ManifestPath))).IsTrue();
    }

    [Test]
    public async Task MissingLockFileIsAnError()
    {
        using var setup = new Setup(withLockFile: false);
        var (task, engine) = setup.Task();

        await Assert.That(task.Execute()).IsFalse();
        await Assert.That(engine.Errors.Single().Code).IsEqualTo(Diagnostics.LockFileMissing);
    }

    [Test]
    public async Task SignedPackageWarns()
    {
        using var setup = new Setup(signed: true);
        var (task, engine) = setup.Task();

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings.Single().Code).IsEqualTo(Diagnostics.PackageSigned);
    }

    [Test]
    public async Task MissingPackageWarns()
    {
        using var setup = new Setup();
        var (task, engine) = setup.Task();
        task.PackOutputs = [];
        task.PackageOutputPath = setup.Temp.Combine("elsewhere");

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings.Single().Code).IsEqualTo(Diagnostics.PackageNotFound);
    }

    [Test]
    public async Task MicrosoftSbomWarns()
    {
        using var setup = new Setup();
        var (task, engine) = setup.Task();
        task.MicrosoftSbomActive = "true";

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings.Single().Code).IsEqualTo(Diagnostics.MicrosoftSbomActive);
    }

    [Test]
    public async Task MissingNuspecIsLowImportance()
    {
        using var setup = new Setup();
        var (task, engine) = setup.Task();
        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Messages.Any(_ => _.Code == Diagnostics.NuspecMissing && _.Message!.Contains("Inner 1.0.0"))).IsTrue();
    }

    [Test]
    public async Task EveryCodeIsDocumented()
    {
        var docs = await File.ReadAllTextAsync(Path.Combine(RepoRoot(), "docs", "DiagnosticCodes.md"));
        foreach (var code in Diagnostics.All)
        {
            await Assert.That(docs).Contains($"## {code}");
        }
    }

    [Test]
    public async Task TargetsPassOnlyRealParameters()
    {
        var targets = System.Xml.Linq.XDocument.Load(Path.Combine(RepoRoot(), "src", "Sbom", "build", "Sbom.targets"));
        var attributes = targets.Descendants()
            .Single(_ => _.Name.LocalName == "SbomTask")
            .Attributes()
            .Select(_ => _.Name.LocalName)
            .Where(_ => _ != "Condition")
            .ToHashSet();
        var properties = typeof(SbomTask)
            .GetProperties()
            .Where(_ => _.DeclaringType == typeof(SbomTask))
            .Select(_ => _.Name)
            .ToHashSet();
        await Assert.That(attributes.SetEquals(properties)).IsTrue();
    }

    static int Scoped(string json, string scope) =>
        json.Split('\n').Count(_ => _.Trim() == $"\"scope\": \"{scope}\",");

    static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(directory!.FullName, "license.txt")))
        {
            directory = directory.Parent;
        }

        return directory.FullName;
    }

    static byte[] Read(ZipArchive archive, string name)
    {
        using var buffer = new MemoryStream();
        using (var stream = archive.GetEntry(name)!.Open())
        {
            stream.CopyTo(buffer);
        }

        return buffer.ToArray();
    }
}
