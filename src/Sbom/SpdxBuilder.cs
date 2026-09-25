namespace Sbom;

/// <summary>
/// Builds the SPDX 3.0.1 JSON-LD document. Output is a pure function of the input: element ids are
/// content hashes, the document namespace is a hash of the whole document, and every list has a
/// total order.
/// </summary>
public static class SpdxBuilder
{
    const string context = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";
    const string defaultNamespaceBase = "https://spdx.org/spdxdocs/";
    const string creationInfo = "_:creationinfo";
    const string zeros = "00000000000000000000000000000000";

    const string contentHashComment = "NuGet contentHash: SHA-512 of the .nupkg excluding its .signature.p7s entry";

    // Same length as a real timestamp. Canonical JSON escapes every quote inside a value, so this
    // exact text can only be the creation info's own property.
    const string createdPlaceholder = "0000-00-00T00:00:00Z";
    const string createdToken = "\"created\": \"" + createdPlaceholder + "\"";

    public static byte[] Build(SbomInput input, DateTimeOffset created) =>
        Finish(Draft(input), created);

    /// <summary>
    /// The document serialized with placeholders for the timestamp and the namespace's unique part,
    /// the only two parts that depend on the timestamp. Finishing it once per candidate timestamp
    /// is far cheaper than serializing again.
    /// </summary>
    public static SpdxDraft Draft(SbomInput input)
    {
        var root = input.Root;
        var id = root.Id ?? "";
        var version = root.Version ?? "";
        var prefix = NamespacePrefix(input.NamespaceBaseUri, id, PurlVersion(version));
        return new(CanonicalJson.Write(BuildGraph(input, prefix + zeros)), prefix);
    }

    /// <summary>
    /// Sets the timestamp, hashes the result, then substitutes the hash for the zeroed unique part.
    /// Both placeholders have the length of what replaces them, and every IRI shares the prefix, so
    /// layout and ordering do not move.
    /// </summary>
    public static byte[] Finish(SpdxDraft draft, DateTimeOffset created)
    {
        var text = draft.Text.Replace(createdToken, $"\"created\": \"{Timestamps.Format(created)}\"");
        var unique = Hashing.Sha256Hex(text)[..32];
        text = text.Replace(draft.Prefix + zeros + "#", draft.Prefix + unique + "#");
        return Encoding.UTF8.GetBytes(text);
    }

    static string NamespacePrefix(string? baseUri, string id, string version)
    {
        var value = baseUri?.Trim();
        if (string.IsNullOrEmpty(value))
        {
            value = defaultNamespaceBase;
        }

        if (!value!.EndsWith("/", StringComparison.Ordinal))
        {
            value += "/";
        }

        return $"{value}{Percent(id)}/{Percent(version)}/";
    }

    sealed class Element(int rank, string sortKey, string local, JsonObject body)
    {
        public int Rank { get; } = rank;
        public string SortKey { get; } = sortKey;
        public string Local { get; } = local;
        public JsonObject Body { get; } = body;
    }

    sealed class Builder(string ns)
    {
        public List<Element> Elements { get; } = [];
        Dictionary<string, string> localKeys = new(StringComparer.Ordinal);
        Dictionary<string, string> agents = new(StringComparer.Ordinal);
        Dictionary<string, string> licenses = new(StringComparer.Ordinal);

        public string Iri(string local) => $"{ns}#{local}";

        public string Local(string kind, string key)
        {
            var local = $"{kind}-{Hashing.ShortHash(key)}";
            var composite = $"{kind}\n{key}";
            if (localKeys.TryGetValue(local, out var existing) &&
                existing != composite)
            {
                throw new InvalidOperationException($"Element id collision: {local}");
            }

            localKeys[local] = composite;
            return local;
        }

        public string Add(int rank, string sortKey, string local, string type, JsonObject body)
        {
            body.Set("spdxId", Iri(local));
            body.Set("type", type);
            body.Set("creationInfo", creationInfo);
            Elements.Add(new(rank, sortKey, local, body));
            return local;
        }

        public string? Agent(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return null;
            }

            name = name!.Trim();
            if (agents.TryGetValue(name, out var local))
            {
                return local;
            }

            local = Local("agent", name);
            agents[name] = local;
            Add(4, name, local, "Agent", new JsonObject().Set("name", name));
            return local;
        }

        public string License(string expression)
        {
            if (licenses.TryGetValue(expression, out var local))
            {
                return local;
            }

            local = Local("license", expression);
            licenses[expression] = local;
            Add(7, expression, local, "simplelicensing_LicenseExpression",
                new JsonObject().Set("simplelicensing_licenseExpression", expression));
            return local;
        }
    }

    sealed record RelationshipSpec(string From, string Type, string? Scope, List<string> To);

    static JsonObject BuildGraph(SbomInput input, string ns)
    {
        var root = input.Root;
        var builder = new Builder(ns);
        var toolName = $"Sbom {input.ToolVersion}";
        var relationships = new List<RelationshipSpec>();

        builder.Add(3, "", "tool", "Tool", new JsonObject()
            .Set("name", toolName)
            .Set("externalIdentifier", PurlIdentifier($"pkg:nuget/Sbom@{Percent(input.ToolVersion)}")));

        var supplier = builder.Agent(input.Supplier ?? root.Authors);
        var createdBy = supplier;
        if (createdBy == null)
        {
            createdBy = builder.Add(4, toolName, "tool-agent", "SoftwareAgent", new JsonObject().Set("name", toolName));
        }

        var dataLicense = builder.License("CC0-1.0");

        // Root package.
        var rootId = root.Id ?? "";
        var rootVersion = root.Version ?? "";
        var rootPurl = Purl(rootId, PurlVersion(rootVersion));
        var rootLocal = builder.Local("package", rootPurl);
        var rootBody = PackageBody(builder, rootId, rootVersion, rootPurl, root, supplier);
        var purpose = "library";
        if (root.IsTool)
        {
            purpose = "application";
        }

        rootBody.Set("software_primaryPurpose", purpose);
        builder.Add(5, "", rootLocal, "software_Package", rootBody);
        AddLicense(builder, relationships, rootLocal, root.LicenseExpression);

        // Dependencies.
        var byKey = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var dependency in input.Dependencies)
        {
            var purl = Purl(dependency.Id, dependency.Version);
            var local = builder.Local("package", purl);
            byKey[dependency.Key] = local;
            JsonObject body;
            if (dependency.Kind == DependencyKind.Project)
            {
                body = PackageBody(builder, dependency.Id, dependency.Version, purl, null, null);
            }
            else
            {
                var metadata = dependency.Metadata;
                body = PackageBody(builder, dependency.Id, dependency.Version, purl, metadata, builder.Agent(metadata?.Authors));
                if (dependency.ContentHashHex != null)
                {
                    body.Set("verifiedUsing", new List<object>
                    {
                        new JsonObject()
                            .Set("type", "Hash")
                            .Set("algorithm", "sha512")
                            .Set("hashValue", dependency.ContentHashHex)
                            .Set("comment", contentHashComment)
                    });
                }
            }

            builder.Add(6, purl, local, "software_Package", body);
            if (dependency.Kind == DependencyKind.Package)
            {
                AddLicense(builder, relationships, local, dependency.Metadata?.LicenseExpression);
            }
        }

        var build = new List<string>();
        var runtime = new List<string>();
        foreach (var dependency in input.Dependencies)
        {
            var local = byKey[dependency.Key];
            if (dependency.IsDirect)
            {
                if (dependency.IsBuildOnly)
                {
                    build.Add(local);
                }
                else
                {
                    runtime.Add(local);
                }
            }

            var children = dependency.DependsOn
                .Where(byKey.ContainsKey)
                .Select(_ => byKey[_])
                .ToList();
            relationships.Add(new(local, "dependsOn", null, children));
        }

        relationships.Add(new(rootLocal, "dependsOn", "build", build));
        relationships.Add(new(rootLocal, "dependsOn", "runtime", runtime));

        // Order everything that is not a relationship, then the relationships against that order.
        var ordered = builder.Elements
            .OrderBy(_ => _.Rank)
            .ThenBy(_ => _.SortKey, StringComparer.Ordinal)
            .ThenBy(_ => _.Local, StringComparer.Ordinal)
            .ToList();

        var sbomLocal = "sbom";
        var documentLocal = "document";
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var i = 0; i < ordered.Count; i++)
        {
            index[ordered[i].Local] = i;
        }

        var relationshipElements = relationships
            .Where(_ => _.To.Count > 0)
            .Select(_ => _ with
            {
                To = _.To
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(to => index[to])
                    .ToList()
            })
            .OrderBy(_ => index[_.From])
            .ThenBy(_ => _.Type, StringComparer.Ordinal)
            .ThenBy(_ => _.Scope ?? "", StringComparer.Ordinal)
            .Select(_ =>
            {
                var key = $"{_.From}|{_.Type}|{_.Scope ?? ""}|{string.Join(",", _.To)}";
                var local = builder.Local("relationship", key);
                var body = new JsonObject()
                    .Set("spdxId", builder.Iri(local))
                    .Set("creationInfo", creationInfo)
                    .Set("from", builder.Iri(_.From))
                    .Set("relationshipType", _.Type)
                    .Set("to", _.To.Select(object (to) => builder.Iri(to)).ToList());
                if (_.Scope == null)
                {
                    body.Set("type", "Relationship");
                }
                else
                {
                    body.Set("type", "LifecycleScopedRelationship");
                    body.Set("scope", _.Scope);
                }

                return (Local: local, Body: body);
            })
            .ToList();

        var memberLocals = ordered
            .Select(_ => _.Local)
            .Concat(relationshipElements.Select(_ => _.Local))
            .ToList();

        var profiles = new List<object>
        {
            "core",
            "simpleLicensing",
            "software"
        };
        var name = $"{rootId} {rootVersion}";

        var sbom = new JsonObject()
            .Set("spdxId", builder.Iri(sbomLocal))
            .Set("type", "software_Sbom")
            .Set("creationInfo", creationInfo)
            .Set("name", name)
            .Set("software_sbomType", new List<object> { "build" })
            .Set("profileConformance", profiles)
            .Set("rootElement", new List<object> { builder.Iri(rootLocal) })
            .Set("element", memberLocals.Select(object (_) => builder.Iri(_)).ToList());

        var document = new JsonObject()
            .Set("spdxId", builder.Iri(documentLocal))
            .Set("type", "SpdxDocument")
            .Set("creationInfo", creationInfo)
            .Set("name", name)
            .Set("dataLicense", builder.Iri(dataLicense))
            .Set("profileConformance", profiles)
            .Set("rootElement", new List<object> { builder.Iri(sbomLocal) })
            .Set("element", new[] { sbomLocal }.Concat(memberLocals).Select(object (_) => builder.Iri(_)).ToList());

        var creation = new JsonObject()
            .Set("@id", creationInfo)
            .Set("type", "CreationInfo")
            .Set("specVersion", "3.0.1")
            .Set("created", createdPlaceholder)
            .Set("createdBy", new List<object> { builder.Iri(createdBy) })
            .Set("createdUsing", new List<object> { builder.Iri("tool") });

        var graph = new List<object>
        {
            creation,
            document,
            sbom
        };
        graph.AddRange(ordered.Select(object (_) => _.Body));
        graph.AddRange(relationshipElements.Select(object (_) => _.Body));

        return new JsonObject()
            .Set("@context", context)
            .Set("@graph", graph);
    }

    static JsonObject PackageBody(Builder builder, string id, string? version, string purl, NuspecMetadata? metadata, string? supplier)
    {
        var body = new JsonObject()
            .Set("name", id)
            .Set("software_packageVersion", version)
            .Set("software_packageUrl", purl)
            .Set("externalIdentifier", PurlIdentifier(purl));
        if (supplier != null)
        {
            body.Set("suppliedBy", builder.Iri(supplier));
        }

        if (metadata == null)
        {
            return body;
        }

        body.Set("software_copyrightText", metadata.Copyright);
        if (Uri.TryCreate(metadata.ProjectUrl, UriKind.Absolute, out _))
        {
            body.Set("software_homePage", metadata.ProjectUrl);
        }

        if (metadata.RepositoryUrl != null)
        {
            body.Set("externalRef", new List<object>
            {
                new JsonObject()
                    .Set("type", "ExternalRef")
                    .Set("externalRefType", "vcs")
                    .Set("locator", new List<object> { metadata.RepositoryUrl })
            });
        }

        if (metadata.RepositoryCommit != null)
        {
            var sourceInfo = $"Built from commit {metadata.RepositoryCommit}";
            if (metadata.RepositoryUrl != null)
            {
                sourceInfo = $"Built from {metadata.RepositoryUrl} at commit {metadata.RepositoryCommit}";
            }

            body.Set("software_sourceInfo", sourceInfo);
        }

        return body;
    }

    static void AddLicense(Builder builder, List<RelationshipSpec> relationships, string from, string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
        {
            return;
        }

        relationships.Add(new(from, "hasDeclaredLicense", null, [builder.License(expression!.Trim())]));
    }

    static List<object> PurlIdentifier(string purl) =>
    [
        new JsonObject()
            .Set("type", "ExternalIdentifier")
            .Set("externalIdentifierType", "packageUrl")
            .Set("identifier", purl)
    ];

    /// <summary>
    /// pkg:nuget/{name}@{version} per ECMA-427. NuGet has no namespace, and no qualifiers are added,
    /// so purls match what consumers and advisory databases use.
    /// </summary>
    public static string Purl(string id, string? version)
    {
        if (string.IsNullOrEmpty(version))
        {
            return $"pkg:nuget/{Percent(id)}";
        }

        return $"pkg:nuget/{Percent(id)}@{Percent(version!)}";
    }

    /// <summary>
    /// Build metadata is not part of NuGet package identity, so it stays out of the purl and the
    /// namespace. The full version is kept in software_packageVersion.
    /// </summary>
    public static string PurlVersion(string version)
    {
        var plus = version.IndexOf('+');
        if (plus >= 0)
        {
            return version.Substring(0, plus);
        }

        return version;
    }

    public static string Percent(string value)
    {
        var builder = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            var ch = (char)b;
            if (ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_' or '~')
            {
                builder.Append(ch);
                continue;
            }

            builder.Append('%');
            builder.Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }
}

public sealed class SpdxDraft(string text, string prefix)
{
    internal string Text { get; } = text;
    internal string Prefix { get; } = prefix;
}
