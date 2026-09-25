using System.Text.Json;

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
    public static List<LockedDependency> Read(string path)
    {
        using var stream = File.OpenRead(path);
        return Read(stream);
    }

    public static List<LockedDependency> Read(Stream stream)
    {
        using var document = JsonDocument.Parse(stream);
        var byKey = new Dictionary<string, LockedDependency>(StringComparer.Ordinal);
        if (!document.RootElement.TryGetProperty("dependencies", out var frameworks) ||
            frameworks.ValueKind != JsonValueKind.Object)
        {
            return [];
        }

        foreach (var framework in frameworks.EnumerateObject())
        {
            // RID-specific graphs (net8.0/win-x64) add runtime.* packages that only matter to a
            // self-contained app, never to a package.
            if (framework.Name.Contains('/'))
            {
                continue;
            }

            ReadFramework(framework.Value, byKey);
        }

        return byKey.Values
            .OrderBy(_ => _.Key, StringComparer.Ordinal)
            .ToList();
    }

    static void ReadFramework(JsonElement framework, Dictionary<string, LockedDependency> byKey)
    {
        if (framework.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        // Within one framework each id resolves to exactly one version, so edges resolve by id.
        var resolved = new Dictionary<string, LockedDependency>(StringComparer.OrdinalIgnoreCase);
        var edges = new List<(LockedDependency From, string ToId)>();
        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in framework.EnumerateObject())
        {
            var value = entry.Value;
            if (value.ValueKind != JsonValueKind.Object)
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
            var key = LockedDependency.MakeKey(entry.Name, version);
            if (!byKey.TryGetValue(key, out var dependency))
            {
                dependency = new(entry.Name, version, kind);
                byKey.Add(key, dependency);
            }

            dependency.ContentHashHex ??= Hashing.Base64ToHex(GetString(value, "contentHash"));
            if (string.Equals(type, "Direct", StringComparison.OrdinalIgnoreCase))
            {
                dependency.IsDirect = true;
            }

            resolved[entry.Name] = dependency;

            if (value.TryGetProperty("dependencies", out var children) &&
                children.ValueKind == JsonValueKind.Object)
            {
                foreach (var child in children.EnumerateObject())
                {
                    edges.Add((dependency, child.Name));
                    referenced.Add(child.Name);
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

    static string? GetString(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var property) &&
            property.ValueKind == JsonValueKind.String)
        {
            return property.GetString();
        }

        return null;
    }
}
