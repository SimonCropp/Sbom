public class ReaderTests
{
    const string lockFile =
        """
        {
          "version": 2,
          "dependencies": {
            ".NETStandard,Version=v2.0": {
              "NETStandard.Library": {
                "type": "Direct",
                "requested": "[2.0.3, )",
                "resolved": "2.0.3",
                "contentHash": "AAEC",
                "dependencies": {
                  "Microsoft.NETCore.Platforms": "1.1.0"
                }
              },
              "Microsoft.NETCore.Platforms": {
                "type": "Transitive",
                "resolved": "1.1.0",
                "contentHash": "AwQF"
              },
              "Pinned": {
                "type": "CentralTransitive",
                "requested": "[3.0.0, )",
                "resolved": "3.0.0"
              },
              "lib": {
                "type": "Project",
                "dependencies": {
                  "Pinned": "[3.0.0, )"
                }
              }
            },
            "net10.0": {
              "Newtonsoft.Json": {
                "type": "Direct",
                "requested": "[13.0.3, )",
                "resolved": "13.0.3"
              },
              "lib": {
                "type": "Project"
              }
            },
            "net10.0/win-x64": {
              "runtime.win-x64.Something": {
                "type": "Transitive",
                "resolved": "1.0.0"
              }
            }
          }
        }
        """;

    [Test]
    public Task LockFileGraph()
    {
        var graph = LockFile.Read(new MemoryStream(Encoding.UTF8.GetBytes(lockFile)));
        return Verify(graph.Select(_ => $"{_.Id} {_.Version} {_.Kind} direct:{_.IsDirect} hash:{_.ContentHashHex} -> {string.Join(",", _.DependsOn)}"))
            .Snapshot(
                """
                [
                  lib  Project direct:True hash: -> pinned/3.0.0,
                  Microsoft.NETCore.Platforms 1.1.0 Package direct:False hash:030405 -> ,
                  NETStandard.Library 2.0.3 Package direct:True hash:000102 -> microsoft.netcore.platforms/1.1.0,
                  Newtonsoft.Json 13.0.3 Package direct:True hash: -> ,
                  Pinned 3.0.0 Package direct:False hash: -> 
                ]
                """);
    }

    [Test]
    public Task Nuspec()
    {
        var xml = TestPackage.Nuspec(
            "A",
            "1.0.0",
            """
            <authors>Acme</authors>
            <license type="expression">MIT OR Apache-2.0</license>
            <projectUrl>https://example.com/a</projectUrl>
            <copyright>© Acme</copyright>
            <repository type="git" url="https://github.com/acme/a" commit="abc" />
            <packageTypes><packageType name="DotnetTool" /></packageTypes>
            """);
        return Verify(NuspecMetadata.Read(new MemoryStream(Encoding.UTF8.GetBytes(xml))));
    }

    [Test]
    public async Task NuspecWithoutNamespace()
    {
        var xml = "<package><metadata><id>A</id><version>1.0</version><licenseUrl>https://licenses.nuget.org/MIT</licenseUrl></metadata></package>";
        var metadata = NuspecMetadata.Read(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
        await Assert.That(metadata.Id).IsEqualTo("A");
        await Assert.That(metadata.LicenseExpression).IsEqualTo("MIT");
    }

    [Test]
    public async Task NuspecRejectsDtd()
    {
        var xml = "<!DOCTYPE package [<!ENTITY x \"y\">]><package><metadata><id>&x;</id></metadata></package>";
        await Assert.That(() => NuspecMetadata.Read(new MemoryStream(Encoding.UTF8.GetBytes(xml)))).Throws<System.Xml.XmlException>();
    }

    [Test]
    public async Task LicenseUrl()
    {
        await Assert.That(NuspecMetadata.FromLicenseUrl("https://licenses.nuget.org/Apache-2.0%20OR%20MIT")).IsEqualTo("Apache-2.0 OR MIT");
        await Assert.That(NuspecMetadata.FromLicenseUrl("https://aka.ms/deprecateLicenseUrl")).IsNull();
        await Assert.That(NuspecMetadata.FromLicenseUrl(null)).IsNull();
    }

    [Test]
    public async Task NormalizeVersion()
    {
        await Assert.That(PackageLocator.NormalizeVersion("1.0")).IsEqualTo("1.0.0");
        await Assert.That(PackageLocator.NormalizeVersion("1.2.3.0")).IsEqualTo("1.2.3");
        await Assert.That(PackageLocator.NormalizeVersion("1.2.3.4")).IsEqualTo("1.2.3.4");
        await Assert.That(PackageLocator.NormalizeVersion("01.2-beta+sha")).IsEqualTo("1.2.0-beta");
    }

    [Test]
    public async Task Timestamps()
    {
        DateTimeOffset Now() => new(2030, 1, 1, 0, 0, 0, 500, TimeSpan.Zero);
        await Assert.That(Sbom.Timestamps.Format(Sbom.Timestamps.Resolve("1767225600", "1", Now))).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(Sbom.Timestamps.Format(Sbom.Timestamps.Resolve("true", "1767225600", Now))).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(Sbom.Timestamps.Format(Sbom.Timestamps.Resolve("2026-02-03T04:05:06+10:00", null, Now))).IsEqualTo("2026-02-02T18:05:06Z");
        await Assert.That(Sbom.Timestamps.Format(Sbom.Timestamps.Resolve("", null, Now))).IsEqualTo("2030-01-01T00:00:00Z");
    }
}
