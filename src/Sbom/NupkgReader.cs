using System.IO.Compression;

namespace Sbom;

public sealed record PackageFile(string Name, string Sha256);

public sealed class PackageScan
{
    public List<PackageFile> Files { get; } = [];
    public NuspecMetadata? Nuspec { get; set; }
    public bool IsSigned { get; set; }
    public bool HasManifest { get; set; }
}

public static class NupkgReader
{
    public const string ManifestDirectory = "_manifest/";
    public const string ManifestPath = "_manifest/spdx_3.0/manifest.spdx.json";
    public const string ManifestHashPath = ManifestPath + ".sha256";

    /// <summary>
    /// Reads only the central directory. Enough to decide whether there is any work to do.
    /// </summary>
    public static (bool HasManifest, bool IsSigned) Probe(string nupkg)
    {
        using var archive = ZipFile.OpenRead(nupkg);
        var hasManifest = false;
        var isSigned = false;
        foreach (var entry in archive.Entries)
        {
            if (string.Equals(entry.FullName, ManifestPath, StringComparison.OrdinalIgnoreCase))
            {
                hasManifest = true;
            }

            if (string.Equals(entry.FullName, ".signature.p7s", StringComparison.OrdinalIgnoreCase))
            {
                isSigned = true;
            }
        }

        return (hasManifest, isSigned);
    }

    public static PackageScan Scan(string nupkg)
    {
        using var stream = File.OpenRead(nupkg);
        return Scan(stream);
    }

    public static PackageScan Scan(Stream stream)
    {
        var scan = new PackageScan();
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName;
            if (name.EndsWith("/", StringComparison.Ordinal))
            {
                continue;
            }

            if (name.StartsWith(ManifestDirectory, StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(name, ManifestPath, StringComparison.OrdinalIgnoreCase))
                {
                    scan.HasManifest = true;
                }

                continue;
            }

            if (string.Equals(name, ".signature.p7s", StringComparison.OrdinalIgnoreCase))
            {
                scan.IsSigned = true;
            }

            if (!name.Contains('/') &&
                name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))
            {
                using var buffer = new MemoryStream();
                using (var entryStream = entry.Open())
                {
                    entryStream.CopyTo(buffer);
                }

                buffer.Position = 0;
                scan.Files.Add(new(name, Hashing.Sha256Hex(buffer)));
                buffer.Position = 0;
                scan.Nuspec = NuspecMetadata.Read(buffer);
                continue;
            }

            using (var entryStream = entry.Open())
            {
                scan.Files.Add(new(name, Hashing.Sha256Hex(entryStream)));
            }
        }

        scan.Files.Sort((x, y) => StringComparer.Ordinal.Compare(x.Name, y.Name));
        return scan;
    }
}
