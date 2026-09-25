using System.Globalization;
using System.Text.Json;
using Json.Schema;

public class SpdxBuilderTests
{
    [Test]
    public async Task GoldenVector()
    {
        var bytes = SpdxBuilder.Build(Golden.Input(), Golden.Created);
        var json = Encoding.UTF8.GetString(bytes);

        // Pins the worked example byte for byte: the namespace's unique part is a hash of the whole
        // document, so any difference anywhere changes it.
        await Assert.That(json).Contains("https://spdx.org/spdxdocs/Acme.Widgets/1.2.3/8fbdb3b144b7f806d6edf18901df4826#document");
        await Assert.That(bytes.Length).IsEqualTo(12969);
    }

    [Test]
    public Task Snapshot() =>
        VerifyJson(Encoding.UTF8.GetString(SpdxBuilder.Build(Golden.Input(), Golden.Created)));

    [Test]
    public async Task OneDraftFinishesForEachTimestamp()
    {
        var draft = SpdxBuilder.Draft(Golden.Input());
        var later = Golden.Created.AddDays(1);

        await Assert.That(SpdxBuilder.Finish(draft, later).SequenceEqual(SpdxBuilder.Build(Golden.Input(), later))).IsTrue();
        await Assert.That(SpdxBuilder.Finish(draft, Golden.Created).SequenceEqual(SpdxBuilder.Build(Golden.Input(), Golden.Created))).IsTrue();
    }

    [Test]
    public async Task ValidatesAgainstTheOfficialSchema()
    {
        var errors = SchemaErrors(SpdxBuilder.Build(Golden.Input(), Golden.Created));
        await Assert.That(errors).IsEmpty();
    }

    [Test]
    public async Task NoDependenciesDocumentValidates()
    {
        var input = Golden.Input();
        var bare = new SbomInput
        {
            Root = new()
            {
                Id = "Bare",
                Version = "1.0.0"
            },
            Dependencies = [],
            ToolVersion = "1.0.0"
        };

        await Assert.That(SchemaErrors(SpdxBuilder.Build(bare, Golden.Created))).IsEmpty();
    }

    [Test]
    public async Task ProjectDependencyValidates()
    {
        var input = Golden.Input();
        var withProject = new SbomInput
        {
            Root = input.Root,
            Dependencies =
            [
                new("lib", null, DependencyKind.Project)
                {
                    IsDirect = true
                }
            ],
            ToolVersion = "1.0.0"
        };

        await Assert.That(SchemaErrors(SpdxBuilder.Build(withProject, Golden.Created))).IsEmpty();
    }

    [Test]
    public async Task IdVectors()
    {
        await Assert.That(Hashing.ShortHash("MIT")).IsEqualTo("e5dcffe836b6ec8a");
        await Assert.That(Hashing.ShortHash("pkg:nuget/Newtonsoft.Json@13.0.3")).IsEqualTo("76db6678a27be3ae");
    }

    [Test]
    public async Task Purl()
    {
        await Assert.That(SpdxBuilder.Purl("Acme.Widgets", "1.2.3+sha.5")).IsEqualTo("pkg:nuget/Acme.Widgets@1.2.3%2Bsha.5");
        await Assert.That(SpdxBuilder.Purl("Ünï.Pkg", "1.0.0-beta.1")).IsEqualTo("pkg:nuget/%C3%9Cn%C3%AF.Pkg@1.0.0-beta.1");
        await Assert.That(SpdxBuilder.Purl("lib", null)).IsEqualTo("pkg:nuget/lib");
    }

    [Test]
    public async Task CultureDoesNotChangeOutput()
    {
        var expected = SpdxBuilder.Build(Golden.Input(), Golden.Created);
        var original = CultureInfo.CurrentCulture;
        try
        {
            foreach (var culture in new[] { "tr-TR", "de-DE", "ar-SA" })
            {
                CultureInfo.CurrentCulture = new(culture);
                await Assert.That(SpdxBuilder.Build(Golden.Input(), Golden.Created).SequenceEqual(expected)).IsTrue();
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Test]
    public async Task DependencyOrderDoesNotChangeOutput()
    {
        var expected = SpdxBuilder.Build(Golden.Input(), Golden.Created);
        var input = Golden.Input();
        var reversed = new SbomInput
        {
            Root = input.Root,
            Dependencies = input.Dependencies.Reverse().ToList(),
            ToolVersion = input.ToolVersion
        };

        await Assert.That(SpdxBuilder.Build(reversed, Golden.Created).SequenceEqual(expected)).IsTrue();
    }

    static readonly Lazy<JsonSchema> schema = new(() =>
        JsonSchema.FromFile(Path.Combine(AppContext.BaseDirectory, "Schemas", "spdx-json-schema-3.0.1.json")));

    internal static List<string> SchemaErrors(byte[] document)
    {
        using var parsed = JsonDocument.Parse(document);
        var result = schema.Value.Evaluate(
            parsed.RootElement,
            new()
            {
                OutputFormat = OutputFormat.List
            });
        if (result.IsValid)
        {
            return [];
        }

        return (result.Details ?? [])
            .Where(_ => _.Errors != null)
            .SelectMany(_ => _.Errors!.Select(error => $"{_.InstanceLocation}: {error.Value}"))
            .Take(20)
            .ToList();
    }
}
