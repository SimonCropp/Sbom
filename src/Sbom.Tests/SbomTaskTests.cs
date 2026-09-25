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
        public string Manifest { get; }
        public string Sidecar => Manifest + ".sha256";
        public string LockFile { get; }
        public string PackageRoot { get; }

        public Setup(bool withLockFile = true)
        {
            Manifest = Temp.Combine("obj", "Release", "sbom", "manifest.spdx.json");
            LockFile = Temp.Combine("packages.lock.json");
            if (withLockFile)
            {
                File.WriteAllText(LockFile, lockFile);
            }

            PackageRoot = Temp.Combine("packages");
            Temp.Write("packages/dep/2.0.0/dep.nuspec",
                TestPackage.Nuspec("Dep", "2.0.0", """<authors>Dep Author</authors><license type="expression">Apache-2.0</license>"""));
        }

        public (SbomTask Task, StubBuildEngine Engine) Task(string sourceDateEpoch = "1767225600")
        {
            var engine = new StubBuildEngine();
            var task = new SbomTask
            {
                BuildEngine = engine,
                ManifestFile = Manifest,
                PackageId = "A",
                PackageVersion = "1.0.0",
                Authors = "Acme",
                PackageLicenseExpression = "MIT",
                LockFile = LockFile,
                PackageRoot = PackageRoot + Path.DirectorySeparatorChar,
                References =
                [
                    new TaskItem("Dep"),
                    new TaskItem("Analyzer", new Dictionary<string, string> { ["PrivateAssets"] = "All" })
                ],
                SourceDateEpoch = sourceDateEpoch
            };
            return (task, engine);
        }

        public string Json => File.ReadAllText(Manifest);

        public void Dispose() => Temp.Dispose();
    }

    [Test]
    public async Task WritesAValidSbom()
    {
        using var setup = new Setup();
        var (task, engine) = setup.Task();

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings).IsEmpty();

        await Assert.That(task.PackageFiles.Select(_ => _.ItemSpec)).IsEquivalentTo([setup.Manifest, setup.Sidecar]);
        await Assert.That(task.PackageFiles.All(_ => _.GetMetadata("PackagePath") == "_manifest/spdx_3.0/")).IsTrue();

        var manifest = await File.ReadAllBytesAsync(setup.Manifest);
        await Assert.That(await File.ReadAllTextAsync(setup.Sidecar)).IsEqualTo(Hashing.Sha256Hex(manifest));
        await Assert.That(SpdxBuilderTests.SchemaErrors(manifest)).IsEmpty();

        var json = setup.Json;
        await Assert.That(json).DoesNotContain(setup.Temp.Path.Replace("\\", "\\\\"));
        await Assert.That(json).DoesNotContain("software_File");
        await Assert.That(json).Contains("\"name\": \"Acme\"");
        await Assert.That(json).Contains("\"name\": \"Dep Author\"");
        await Assert.That(json).Contains("\"simplelicensing_licenseExpression\": \"MIT\"");
        await Assert.That(json).Contains("\"simplelicensing_licenseExpression\": \"Apache-2.0\"");
        await Assert.That(json).Contains("\"created\": \"2026-01-01T00:00:00Z\"");
        await Assert.That(Scoped(json, "build")).IsEqualTo(1);
        await Assert.That(Scoped(json, "runtime")).IsEqualTo(1);
    }

    [Test]
    public async Task RootComesFromPackProperties()
    {
        using var setup = new Setup();
        var (task, _) = setup.Task();
        task.PackageVersion = "1.0+sha.5";
        task.PackageLicenseExpression = "";
        task.PackageLicenseUrl = "https://licenses.nuget.org/Apache-2.0%20OR%20MIT";
        task.PackageType = "DotnetTool";
        task.PackageProjectUrl = "https://example.com/a";
        task.RepositoryUrl = "https://github.com/acme/a";
        task.RepositoryCommit = "abc";

        await Assert.That(task.Execute()).IsTrue();
        var json = setup.Json;
        // Normalized as NuGet writes it into the nuspec; build metadata stays out of the purl.
        await Assert.That(json).Contains("\"software_packageVersion\": \"1.0.0+sha.5\"");
        await Assert.That(json).Contains("\"software_packageUrl\": \"pkg:nuget/A@1.0.0\"");
        await Assert.That(json).Contains("\"software_primaryPurpose\": \"application\"");
        await Assert.That(json).Contains("\"simplelicensing_licenseExpression\": \"Apache-2.0 OR MIT\"");
        await Assert.That(json).Contains("\"software_homePage\": \"https://example.com/a\"");
        await Assert.That(json).Contains("\"software_sourceInfo\": \"Built from https://github.com/acme/a at commit abc\"");
    }

    [Test]
    public async Task UnchangedManifestIsNotRewritten()
    {
        using var setup = new Setup();
        // Left to the clock, so only reusing the previous timestamp keeps the bytes equal.
        await Assert.That(setup.Task(sourceDateEpoch: "").Task.Execute()).IsTrue();
        var bytes = await File.ReadAllBytesAsync(setup.Manifest);
        var old = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(setup.Manifest, old);
        File.SetLastWriteTimeUtc(setup.Sidecar, old);

        await Task.Delay(1100);
        var (task, engine) = setup.Task(sourceDateEpoch: "");
        await Assert.That(task.Execute()).IsTrue();

        await Assert.That((await File.ReadAllBytesAsync(setup.Manifest)).SequenceEqual(bytes)).IsTrue();
        await Assert.That(File.GetLastWriteTimeUtc(setup.Manifest)).IsEqualTo(old);
        await Assert.That(File.GetLastWriteTimeUtc(setup.Sidecar)).IsEqualTo(old);
        await Assert.That(task.PackageFiles.Length).IsEqualTo(2);
        await Assert.That(engine.Messages.Any(_ => _.Message!.Contains("unchanged"))).IsTrue();
    }

    [Test]
    public async Task ChangedInputsRewriteTheManifest()
    {
        using var setup = new Setup();
        await Assert.That(setup.Task().Task.Execute()).IsTrue();
        var (task, _) = setup.Task();
        task.Authors = "Someone Else";

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(setup.Json).Contains("\"name\": \"Someone Else\"");
        await Assert.That(await File.ReadAllTextAsync(setup.Sidecar)).IsEqualTo(Hashing.Sha256Hex(await File.ReadAllBytesAsync(setup.Manifest)));
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

        var first = await File.ReadAllBytesAsync(one.Manifest);
        var second = await File.ReadAllBytesAsync(two.Manifest);
        await Assert.That(first.SequenceEqual(second)).IsTrue();
    }

    [Test]
    public async Task NoLockFileAndNoAssetsFileIsAnError()
    {
        using var setup = new Setup(withLockFile: false);
        var (task, engine) = setup.Task();

        await Assert.That(task.Execute()).IsFalse();
        await Assert.That(engine.Errors.Single().Code).IsEqualTo(Diagnostics.LockFileMissing);
        await Assert.That(task.PackageFiles).IsEmpty();
    }

    [Test]
    public async Task FallsBackToTheAssetsFile()
    {
        using var setup = new Setup(withLockFile: false);
        var assets = setup.Temp.Write(
            "obj/project.assets.json",
            """
            {
              "version": 4,
              "targets": {
                "net10.0": {
                  "Dep/2.0.0": {
                    "type": "package",
                    "dependencies": {
                      "Inner": "1.0.0"
                    }
                  },
                  "Inner/1.0.0": {
                    "type": "package"
                  },
                  "Analyzer/1.0.0": {
                    "type": "package"
                  }
                },
                "net10.0/win-x64": {
                  "runtime.win-x64.Native/1.0.0": {
                    "type": "package"
                  }
                }
              },
              "libraries": {
                "Dep/2.0.0": {
                  "sha512": "AAEC",
                  "type": "package"
                }
              },
              "projectFileDependencyGroups": {
                "net10.0": [
                  "Dep >= 2.0.0",
                  "Analyzer >= 1.0.0"
                ]
              }
            }
            """);
        var (task, engine) = setup.Task();
        task.AssetsFile = assets;

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings).IsEmpty();
        await Assert.That(SpdxBuilderTests.SchemaErrors(await File.ReadAllBytesAsync(setup.Manifest))).IsEmpty();

        var json = setup.Json;
        await Assert.That(json).Contains("pkg:nuget/Inner@1.0.0");
        await Assert.That(json).Contains("\"hashValue\": \"000102\"");
        await Assert.That(json).DoesNotContain("runtime.win-x64.Native");
        await Assert.That(Scoped(json, "build")).IsEqualTo(1);
        await Assert.That(Scoped(json, "runtime")).IsEqualTo(1);
    }

    [Test]
    public Task AssetsGraph()
    {
        var graph = AssetsFile.ReadText(
            """
            {
              "targets": {
                ".NETStandard,Version=v2.0": {
                  "A/1.0.0": { "type": "package", "dependencies": { "B": "[2.0.0, )" } },
                  "B/2.1.0": { "type": "package" },
                  "Lib/1.0.0": { "type": "project", "dependencies": { "B": "2.1.0" } }
                },
                "net10.0": {
                  "A/1.0.0": { "type": "package" }
                }
              },
              "projectFileDependencyGroups": {
                ".NETStandard,Version=v2.0": [ "A >= 1.0.0", "Lib >= 1.0.0" ],
                "net10.0": [ "A >= 1.0.0" ]
              }
            }
            """);
        return Verify(graph.Select(_ => $"{_.Id} {_.Version} {_.Kind} direct:{_.IsDirect} -> {string.Join(",", _.DependsOn)}"))
            .Snapshot(
                """
                [
                  A 1.0.0 Package direct:True -> b/2.1.0,
                  B 2.1.0 Package direct:False -> ,
                  Lib 1.0.0 Project direct:True -> b/2.1.0
                ]
                """);
    }

    [Test]
    public async Task NuspecFileWarnsAndWritesNothing()
    {
        using var setup = new Setup();
        var (task, engine) = setup.Task();
        task.NuspecFile = setup.Temp.Combine("A.nuspec");

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings.Single().Code).IsEqualTo(Diagnostics.NuspecFileNotSupported);
        await Assert.That(task.PackageFiles).IsEmpty();
        await Assert.That(File.Exists(setup.Manifest)).IsFalse();
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
    public async Task StaleLockFileWarnsButStillWrites()
    {
        using var setup = new Setup();
        var assets = setup.Temp.Write("obj/project.assets.json", "{}");
        File.SetLastWriteTimeUtc(setup.LockFile, DateTime.UtcNow.AddHours(-1));
        File.SetLastWriteTimeUtc(assets, DateTime.UtcNow);
        var (task, engine) = setup.Task();
        task.AssetsFile = assets;

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings.Single().Code).IsEqualTo(Diagnostics.LockFileStale);
        await Assert.That(File.Exists(setup.Manifest)).IsTrue();
    }

    [Test]
    public async Task FreshLockFileDoesNotWarn()
    {
        using var setup = new Setup();
        var assets = setup.Temp.Write("obj/project.assets.json", "{}");
        File.SetLastWriteTimeUtc(assets, DateTime.UtcNow.AddHours(-1));
        File.SetLastWriteTimeUtc(setup.LockFile, DateTime.UtcNow);
        var (task, engine) = setup.Task();
        task.AssetsFile = assets;

        await Assert.That(task.Execute()).IsTrue();
        await Assert.That(engine.Warnings).IsEmpty();
    }

    [Test]
    public async Task UnexpectedFailureFailsTheBuild()
    {
        using var setup = new Setup();
        // A file where the manifest's directory should be.
        setup.Temp.Write("obj/Release/sbom", "");
        var (task, engine) = setup.Task();

        await Assert.That(task.Execute()).IsFalse();
        await Assert.That(engine.Errors.Single().Code).IsEqualTo(Diagnostics.Failed);
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
        var element = targets.Descendants().Single(_ => _.Name.LocalName == "SbomTask");
        var attributes = element
            .Attributes()
            .Select(_ => _.Name.LocalName)
            .Where(_ => _ != "Condition")
            .ToHashSet();
        var outputs = element
            .Elements()
            .Where(_ => _.Name.LocalName == "Output")
            .Select(_ => _.Attribute("TaskParameter")!.Value)
            .ToHashSet();
        var properties = typeof(SbomTask)
            .GetProperties()
            .Where(_ => _.DeclaringType == typeof(SbomTask))
            .ToList();
        await Assert.That(attributes.SetEquals(properties.Where(_ => !IsOutput(_)).Select(_ => _.Name))).IsTrue();
        await Assert.That(outputs.SetEquals(properties.Where(IsOutput).Select(_ => _.Name))).IsTrue();
    }

    static bool IsOutput(PropertyInfo property) =>
        property.IsDefined(typeof(OutputAttribute), false);

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
}
