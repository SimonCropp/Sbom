namespace Sbom.IntegrationTests;

public static class TestEnvironment
{
    static readonly Lazy<string> repoRoot = new(FindRepoRoot);

    public static string RepoRoot => repoRoot.Value;
    public static string NugetsDirectory => Path.Combine(RepoRoot, "nugets");
    public static string FixturesDirectory => Path.Combine(RepoRoot, "IntegrationTests", "Fixtures");

    /// <summary>
    /// Walks up from the test binaries looking for license.txt, so nothing here depends on how deep
    /// the output directory happens to be.
    /// </summary>
    static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null &&
               !File.Exists(Path.Combine(directory.FullName, "license.txt")))
        {
            directory = directory.Parent;
        }

        if (directory == null)
        {
            throw new("Could not locate the repo root: no license.txt above the test binaries.");
        }

        return directory.FullName;
    }

    public static string MakeWorkDirectory([CallerMemberName] string caller = "")
    {
        var path = Path.Combine(Path.GetTempPath(), "sbom-it", $"{caller}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    public static void CopyDirectory(string source, string target)
    {
        Directory.CreateDirectory(target);
        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, file);
            if (relative.StartsWith("bin", StringComparison.OrdinalIgnoreCase) ||
                relative.StartsWith("obj", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var destination = Path.Combine(target, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(file, destination, overwrite: true);
        }
    }

    public static void WriteNugetConfig(string directory, string feed)
    {
        var content = $"""
                       <?xml version="1.0" encoding="utf-8"?>
                       <configuration>
                         <packageSources>
                           <clear />
                           <add key="local" value="{feed}" />
                           <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
                         </packageSources>
                       </configuration>
                       """;
        File.WriteAllText(Path.Combine(directory, "nuget.config"), content);
    }
}
