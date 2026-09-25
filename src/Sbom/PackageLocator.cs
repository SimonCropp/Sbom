namespace Sbom;

public static class PackageLocator
{
    /// <summary>
    /// NuGetPackOutput is the authority when it names a file that exists. On SDK 10 and older it is
    /// computed from PackageId/PackageVersion alone, so for NuspecFile packs and
    /// OutputFileNamesWithoutVersion it can name a file that was never written; the file-name
    /// fallbacks cover those.
    /// </summary>
    public static string? Find(IEnumerable<string> packOutputs, string outputDirectory, string id, string version)
    {
        foreach (var output in packOutputs)
        {
            if (output.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase) &&
                !output.EndsWith(".symbols.nupkg", StringComparison.OrdinalIgnoreCase) &&
                File.Exists(output))
            {
                return output;
            }
        }

        if (outputDirectory.Length == 0 || id.Length == 0)
        {
            return null;
        }

        var candidates = new List<string>();
        if (version.Length > 0)
        {
            candidates.Add($"{id}.{version}.nupkg");
            var normalized = NormalizeVersion(version);
            if (normalized != version)
            {
                candidates.Add($"{id}.{normalized}.nupkg");
            }
        }

        candidates.Add($"{id}.nupkg");

        foreach (var candidate in candidates)
        {
            var path = Path.Combine(outputDirectory, candidate);
            if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    /// <summary>
    /// The version NuGet puts in a package file name: build metadata dropped, at least three parts,
    /// a fourth part only when it is not zero.
    /// </summary>
    public static string NormalizeVersion(string version)
    {
        var plus = version.IndexOf('+');
        if (plus >= 0)
        {
            version = version.Substring(0, plus);
        }

        var dash = version.IndexOf('-');
        var release = version;
        var suffix = "";
        if (dash >= 0)
        {
            release = version.Substring(0, dash);
            suffix = version.Substring(dash);
        }

        var parts = release.Split('.').ToList();
        if (!parts.All(_ => _.Length > 0 && _.All(char.IsDigit)))
        {
            return version;
        }

        var numbers = parts
            .Select(_ => int.Parse(_, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture))
            .ToList();
        while (numbers.Count < 3)
        {
            numbers.Add("0");
        }

        if (numbers.Count == 4 && numbers[3] == "0")
        {
            numbers.RemoveAt(3);
        }

        return string.Join(".", numbers) + suffix;
    }
}
