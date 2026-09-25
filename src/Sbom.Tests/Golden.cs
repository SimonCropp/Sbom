/// <summary>
/// The worked example from the SPDX design: a tiny package with one runtime and one build-only
/// dependency. Every value is fixed, so the output is a golden vector.
/// </summary>
static class Golden
{
    public static SbomInput Input() =>
        new()
        {
            Root = new()
            {
                Id = "Acme.Widgets",
                Version = "1.2.3",
                Authors = "Acme",
                LicenseExpression = "MIT",
                ProjectUrl = "https://github.com/acme/widgets",
                RepositoryUrl = "https://github.com/acme/widgets",
                RepositoryCommit = "0123456789abcdef0123456789abcdef01234567",
                Copyright = "Copyright © Acme 2026"
            },
            Files =
            [
                new("Acme.Widgets.nuspec", new('3', 64)),
                new("[Content_Types].xml", new('1', 64)),
                new("_rels/.rels", new('2', 64)),
                new("lib/net8.0/Acme.Widgets.dll", new('4', 64)),
                new("package/services/metadata/core-properties/0123456789abcdef0123456789abcdef.psmdcp", new('5', 64))
            ],
            Dependencies =
            [
                new("Newtonsoft.Json", "13.0.3", DependencyKind.Package)
                {
                    IsDirect = true,
                    ContentHashHex = new('a', 128),
                    Metadata = new()
                    {
                        Authors = "James Newton-King",
                        LicenseExpression = "MIT",
                        ProjectUrl = "https://www.newtonsoft.com/json",
                        Copyright = "Copyright © James Newton-King 2008",
                        RepositoryUrl = "https://github.com/JamesNK/Newtonsoft.Json",
                        RepositoryCommit = "0a2e291c0d9c0c7675d445703e51750363a549ef"
                    }
                },
                new("Polyfill", "9.0.0", DependencyKind.Package)
                {
                    IsDirect = true,
                    IsBuildOnly = true,
                    ContentHashHex = new('b', 128),
                    Metadata = new()
                    {
                        Authors = "Simon Cropp",
                        LicenseExpression = "MIT",
                        ProjectUrl = "https://github.com/SimonCropp/Polyfill"
                    }
                }
            ],
            Created = DateTimeOffset.FromUnixTimeSeconds(1767225600),
            ToolVersion = "1.0.0"
        };
}
