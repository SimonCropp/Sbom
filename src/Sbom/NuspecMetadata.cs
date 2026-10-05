namespace Sbom;

public sealed class NuspecMetadata
{
    public string? Id { get; set; }
    public string? Version { get; set; }
    public string? Authors { get; set; }
    public string? LicenseExpression { get; set; }
    public string? ProjectUrl { get; set; }
    public string? Copyright { get; set; }
    public string? RepositoryUrl { get; set; }
    public string? RepositoryCommit { get; set; }
    public bool IsTool { get; set; }

    public static NuspecMetadata? TryReadFile(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            using var stream = File.OpenRead(path);
            return Read(stream);
        }
        catch (XmlException)
        {
            return null;
        }
    }

    /// <summary>
    /// Matches by local name so every nuspec namespace version reads the same. DTDs are refused.
    /// </summary>
    public static NuspecMetadata Read(Stream stream)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreWhitespace = true
        };
        var metadata = new NuspecMetadata();
        string? licenseUrl = null;
        using var reader = XmlReader.Create(stream, settings);
        var depth = -1;
        while (!reader.EOF)
        {
            if (reader.NodeType != XmlNodeType.Element)
            {
                reader.Read();
                continue;
            }

            var name = reader.LocalName;
            if (name == "metadata")
            {
                depth = reader.Depth;
                reader.Read();
                continue;
            }

            if (depth < 0)
            {
                reader.Read();
                continue;
            }

            if (name == "repository" && reader.Depth == depth + 1)
            {
                metadata.RepositoryUrl = Clean(reader.GetAttribute("url"));
                metadata.RepositoryCommit = Clean(reader.GetAttribute("commit"));
                reader.Read();
                continue;
            }

            if (name == "packageType")
            {
                if (string.Equals(reader.GetAttribute("name"), "DotnetTool", StringComparison.OrdinalIgnoreCase))
                {
                    metadata.IsTool = true;
                }

                reader.Read();
                continue;
            }

            if (reader.Depth != depth + 1 || reader.IsEmptyElement)
            {
                reader.Read();
                continue;
            }

            switch (name)
            {
                case "id":
                    metadata.Id = Clean(reader.ReadElementContentAsString());
                    break;
                case "version":
                    metadata.Version = Clean(reader.ReadElementContentAsString());
                    break;
                case "authors":
                    metadata.Authors = Clean(reader.ReadElementContentAsString());
                    break;
                case "projectUrl":
                    metadata.ProjectUrl = Clean(reader.ReadElementContentAsString());
                    break;
                case "copyright":
                    metadata.Copyright = Clean(reader.ReadElementContentAsString());
                    break;
                case "licenseUrl":
                    licenseUrl = Clean(reader.ReadElementContentAsString());
                    break;
                case "license":
                    var type = reader.GetAttribute("type");
                    var value = Clean(reader.ReadElementContentAsString());
                    if (string.Equals(type, "expression", StringComparison.OrdinalIgnoreCase))
                    {
                        metadata.LicenseExpression = value;
                    }

                    break;
                default:
                    reader.Read();
                    break;
            }
        }

        metadata.LicenseExpression ??= FromLicenseUrl(licenseUrl);
        return metadata;
    }

    const string licensesPrefix = "https://licenses.nuget.org/";

    /// <summary>
    /// NuGet writes https://licenses.nuget.org/{expression} as the legacy licenseUrl of any package
    /// packed with a license expression. Any other URL says nothing checkable.
    /// </summary>
    public static string? FromLicenseUrl(string? url)
    {
        if (url == null ||
            !url.StartsWith(licensesPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var expression = Uri.UnescapeDataString(url.Substring(licensesPrefix.Length)).Trim();
        if (expression.Length == 0)
        {
            return null;
        }

        foreach (var ch in expression)
        {
            if (!char.IsLetterOrDigit(ch) &&
                ch != '.' &&
                ch != '-' &&
                ch != '+' &&
                ch != ' ' &&
                ch != '(' &&
                ch != ')' &&
                ch != ':')
            {
                return null;
            }
        }

        return expression;
    }

    static string? Clean(string? value)
    {
        if (value == null)
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        return trimmed;
    }
}
