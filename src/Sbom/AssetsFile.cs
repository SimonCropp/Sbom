namespace Sbom;

/// <summary>
/// Reads obj/project.assets.json, the resolved graph restore always writes. Used when the project
/// has no packages.lock.json. It carries the same information: every resolved library per
/// framework, direct and transitive, with its SHA-512 content hash and its own dependencies.
/// </summary>
public static class AssetsFile
{
    public static List<LockedDependency> Read(string path) =>
        ReadText(File.ReadAllText(path));

    public static List<LockedDependency> ReadText(string json)
    {
        if (JsonReader.Parse(json) is not JsonObject root ||
            !root.TryGetValue("targets", out var targetsValue) ||
            targetsValue is not JsonObject targets)
        {
            return [];
        }

        var libraries = root.TryGetValue("libraries", out var librariesValue) ? librariesValue as JsonObject : null;
        var groups = root.TryGetValue("projectFileDependencyGroups", out var groupsValue) ? groupsValue as JsonObject : null;
        var byKey = new Dictionary<string, LockedDependency>(StringComparer.Ordinal);

        foreach (var target in targets)
        {
            // RID-specific graphs (net8.0/win-x64) add runtime.* packages that only matter to a
            // self-contained app, never to a package.
            if (target.Key.Contains('/') ||
                target.Value is not JsonObject entries)
            {
                continue;
            }

            // Targets and dependency groups share their key in every assets version: the alias in
            // v4, the framework name in v3.
            object? group = null;
            groups?.TryGetValue(target.Key, out group);
            ReadTarget(entries, group as List<object?>, libraries, byKey);
        }

        return byKey.Values
            .OrderBy(_ => _.Key, StringComparer.Ordinal)
            .ToList();
    }

    static void ReadTarget(
        JsonObject target,
        List<object?>? directGroup,
        JsonObject? libraries,
        Dictionary<string, LockedDependency> byKey)
    {
        var resolved = new Dictionary<string, LockedDependency>(StringComparer.OrdinalIgnoreCase);
        var edges = new List<(LockedDependency From, string ToId)>();

        foreach (var entry in target)
        {
            if (entry.Value is not JsonObject value)
            {
                continue;
            }

            // Keys are "Id/Version".
            var slash = entry.Key.IndexOf('/');
            if (slash <= 0)
            {
                continue;
            }

            var id = entry.Key.Substring(0, slash);
            var version = entry.Key.Substring(slash + 1);
            var kind = DependencyKind.Package;
            if (string.Equals(value.TryGetValue("type", out var type) ? type as string : null, "project", StringComparison.OrdinalIgnoreCase))
            {
                kind = DependencyKind.Project;
            }

            var key = LockedDependency.MakeKey(id, version);
            if (!byKey.TryGetValue(key, out var dependency))
            {
                dependency = new(id, version, kind);
                byKey.Add(key, dependency);
            }

            if (dependency.ContentHashHex == null &&
                libraries != null &&
                libraries.TryGetValue(entry.Key, out var library) &&
                library is JsonObject libraryObject &&
                libraryObject.TryGetValue("sha512", out var sha512))
            {
                dependency.ContentHashHex = Hashing.Base64ToHex(sha512 as string);
            }

            resolved[id] = dependency;

            if (value.TryGetValue("dependencies", out var children) &&
                children is JsonObject childObject)
            {
                foreach (var child in childObject)
                {
                    edges.Add((dependency, child.Key));
                }
            }
        }

        // Direct dependencies are listed as "Id >= range" (or just "Id").
        if (directGroup != null)
        {
            foreach (var item in directGroup)
            {
                if (item is not string text)
                {
                    continue;
                }

                var space = text.IndexOf(' ');
                var id = text;
                if (space > 0)
                {
                    id = text.Substring(0, space);
                }

                if (resolved.TryGetValue(id, out var direct))
                {
                    direct.IsDirect = true;
                }
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
}
