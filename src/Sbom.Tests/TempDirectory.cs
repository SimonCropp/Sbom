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

    /// <summary>
    /// A NuGet-shaped package: OPC parts, a root nuspec and one library, all stamped with one time.
    /// </summary>
    public static void Create(string path, string id, string version, string nuspecExtra = "", bool signed = false)
    {
        using var stream = File.Create(path);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create);
        var time = new DateTimeOffset(2026, 3, 4, 5, 6, 8, TimeSpan.Zero);
        Add(archive, "_rels/.rels", "<Relationships/>", time);
        Add(archive, $"{id}.nuspec", Nuspec(id, version, nuspecExtra), time);
        Add(archive, $"lib/net10.0/{id}.dll", "not really a dll", time);
        Add(archive, "[Content_Types].xml", "<Types/>", time);
        if (signed)
        {
            Add(archive, ".signature.p7s", "signature", time);
        }
    }

    static void Add(ZipArchive archive, string name, string content, DateTimeOffset time)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        entry.LastWriteTime = time;
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }
}
