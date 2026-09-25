public sealed class TempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "SbomTests", Guid.NewGuid().ToString("N"));

    public TempDirectory() =>
        Directory.CreateDirectory(Path);

    public string Combine(params string[] parts) =>
        System.IO.Path.Combine([Path, .. parts]);

    public string Write(string relative, string content)
    {
        var path = Combine(relative);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, true);
        }
        catch (IOException)
        {
        }
    }
}

static class TestPackage
{
    public static string Nuspec(string id, string version, string extra = "") =>
        $"""
         <?xml version="1.0" encoding="utf-8"?>
         <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
           <metadata>
             <id>{id}</id>
             <version>{version}</version>
             {extra}
           </metadata>
         </package>
         """;
}
