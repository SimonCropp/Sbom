namespace Sbom;

// ProjectNames: referenced projects' NuGet names, by full project path.
public sealed record AssetsContent(List<LockedDependency> Dependencies, Dictionary<string, string> ProjectNames);

/// <summary>
/// Reads obj/project.assets.json, the resolved graph restore always writes. Used when the project
/// has no packages.lock.json. It carries the same information: every resolved library per
/// framework, direct and transitive, with its SHA-512 content hash and its own dependencies.
/// </summary>
public static class AssetsFile
{
    public static AssetsContent Read(string path) =>
        ReadText(File.ReadAllText(path));

    public static AssetsContent ReadText(string json)
    {
        if (JsonReader.Parse(json) is not JsonObject root)
        {
            return new([], []);
        }

        var libraries = root.TryGetValue("libraries", out var librariesValue) ? librariesValue as JsonObject : null;
        var projectNames = ProjectNames(root, libraries);
        if (!root.TryGetValue("targets", out var targetsValue) ||
            targetsValue is not JsonObject targets)
        {
            return new([], projectNames);
        }

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

        var dependencies = byKey.Values
            .OrderBy(_ => _.Key, StringComparer.Ordinal)
            .ToList();
        return new(dependencies, projectNames);
    }

    /// <summary>
    /// NuGet names a referenced project by its PackageId (else AssemblyName, else file name), which
    /// only that project's own evaluation knows. Its library entry records the project's path
    /// relative to the restored project, so the name can be found from a reference's full path.
    /// </summary>
    static Dictionary<string, string> ProjectNames(JsonObject root, JsonObject? libraries)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (libraries == null ||
            !root.TryGetValue("project", out var projectValue) ||
            projectValue is not JsonObject project ||
            !project.TryGetValue("restore", out var restoreValue) ||
            restoreValue is not JsonObject restore ||
            !restore.TryGetValue("projectPath", out var projectPathValue) ||
            projectPathValue is not string { Length: > 0 } projectPath)
        {
            return names;
        }

        var directory = Path.GetDirectoryName(projectPath)!;
        foreach (var library in libraries)
        {
            if (library.Value is not JsonObject value ||
                !string.Equals(value.TryGetValue("type", out var type) ? type as string : null, "project", StringComparison.OrdinalIgnoreCase) ||
                !value.TryGetValue("msbuildProject", out var pathValue) ||
                pathValue is not string { Length: > 0 } relative)
            {
                continue;
            }

            var slash = library.Key.IndexOf('/');
            if (slash <= 0)
            {
                continue;
            }

            names[Path.GetFullPath(Path.Combine(directory, relative))] = library.Key.Substring(0, slash);
        }

        return names;
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
