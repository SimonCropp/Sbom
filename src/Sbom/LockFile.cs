namespace Sbom;

public enum DependencyKind
{
    Package,
    Project
}

public sealed class LockedDependency(string id, string? version, DependencyKind kind)
{
    public string Id { get; } = id;
    public string? Version { get; } = version;
    public DependencyKind Kind { get; } = kind;
    public string? ContentHashHex { get; set; }
    public bool IsDirect { get; set; }
    public SortedSet<string> DependsOn { get; } = new(StringComparer.Ordinal);

    public string Key => MakeKey(Id, Version);

    public static string MakeKey(string id, string? version) =>
        $"{id.ToLowerInvariant()}/{version?.ToLowerInvariant()}";
}

/// <summary>
/// Reads packages.lock.json: every resolved package per framework, direct or transitive, with its
/// contentHash and its own dependencies.
/// </summary>
public static class LockFile
{
    public static List<LockedDependency> Read(string path) =>
        ReadText(File.ReadAllText(path));

    public static List<LockedDependency> Read(Stream stream)
    {
        using var reader = new StreamReader(stream);
        return ReadText(reader.ReadToEnd());
    }

    public static List<LockedDependency> ReadText(string json)
    {
        var byKey = new Dictionary<string, LockedDependency>(StringComparer.Ordinal);
        if (JsonReader.Parse(json) is not JsonObject root ||
            !root.TryGetValue("dependencies", out var value) ||
            value is not JsonObject frameworks)
        {
            return [];
        }

        foreach (var framework in frameworks)
        {
            // RID-specific graphs (net8.0/win-x64) add runtime.* packages that only matter to a
            // self-contained app, never to a package.
            if (framework.Key.Contains('/'))
            {
                continue;
            }

            if (framework.Value is JsonObject entries)
            {
                ReadFramework(entries, byKey);
            }
        }

        return byKey.Values
            .OrderBy(_ => _.Key, StringComparer.Ordinal)
            .ToList();
    }

    static void ReadFramework(JsonObject framework, Dictionary<string, LockedDependency> byKey)
    {
        // Within one framework each id resolves to exactly one version, so edges resolve by id.
        var resolved = new Dictionary<string, LockedDependency>(StringComparer.OrdinalIgnoreCase);
        var edges = new List<(LockedDependency From, string ToId)>();
        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in framework)
        {
            if (entry.Value is not JsonObject value)
            {
                continue;
            }

            var type = GetString(value, "type");
            var kind = DependencyKind.Package;
            if (string.Equals(type, "Project", StringComparison.OrdinalIgnoreCase))
            {
                kind = DependencyKind.Project;
            }

            var version = GetString(value, "resolved");
            var key = LockedDependency.MakeKey(entry.Key, version);
            if (!byKey.TryGetValue(key, out var dependency))
            {
                dependency = new(entry.Key, version, kind);
                byKey.Add(key, dependency);
            }

            dependency.ContentHashHex ??= Hashing.Base64ToHex(GetString(value, "contentHash"));
            if (string.Equals(type, "Direct", StringComparison.OrdinalIgnoreCase))
            {
                dependency.IsDirect = true;
            }

            resolved[entry.Key] = dependency;

            if (value.TryGetValue("dependencies", out var children) &&
                children is JsonObject childObject)
            {
                foreach (var child in childObject)
                {
                    edges.Add((dependency, child.Key));
                    referenced.Add(child.Key);
                }
            }
        }

        // A project entry is direct unless another entry in this framework pulls it in.
        foreach (var dependency in resolved.Values)
        {
            if (dependency.Kind == DependencyKind.Project &&
                !referenced.Contains(dependency.Id))
            {
                dependency.IsDirect = true;
            }
        }

        foreach (var (from, toId) in edges)
        {
            if (resolved.TryGetValue(toId, out var to) &&
                !ReferenceEquals(from, to))
            {
                from.DependsOn.Add(to.Key);
            }
        }
    }

    static string? GetString(JsonObject element, string name)
    {
        if (element.TryGetValue(name, out var property))
        {
            return property as string;
        }

        return null;
    }
}
