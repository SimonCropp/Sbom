namespace Sbom;

public static class Versions
{
    /// <summary>
    /// The version NuGet writes into the packed nuspec: at least three parts, a fourth part only when
    /// it is not zero, leading zeros dropped, prerelease and build metadata kept.
    /// </summary>
    public static string Normalize(string version)
    {
        var metadata = "";
        var plus = version.IndexOf('+');
        if (plus >= 0)
        {
            metadata = version.Substring(plus);
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
        if (parts.Count > 4 ||
            !parts.All(_ => _.Length > 0 && _.All(char.IsDigit)))
        {
            return version + metadata;
        }

        var numbers = parts
            .Select(_ => int.Parse(_, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture))
            .ToList();
        while (numbers.Count < 3)
        {
            numbers.Add("0");
        }

        if (numbers is [_, _, _, "0"])
        {
            numbers.RemoveAt(3);
        }

        return string.Join(".", numbers) + suffix + metadata;
    }
}
