using System.Text.Json;

public class CanonicalJsonTests
{
    const string awkward = "quote\" backslash\\ tab\t newline\n return\r backspace\b formfeed\f bell\u0007 nul\0 copyright© plus+ html<&>'";

    [Test]
    public async Task EscapesOnlyWhatJsonRequires()
    {
        var json = CanonicalJson.Write(new JsonObject().Set("a", awkward));

        await Assert.That(json).IsEqualTo(
            "{\n  \"a\": \"quote\\\" backslash\\\\ tab\\t newline\\n return\\r backspace\\b formfeed\\f bell\\u0007 nul\\u0000 copyright© plus+ html<&>'\"\n}\n");
    }

    [Test]
    public async Task RoundTrips()
    {
        var json = CanonicalJson.Write(new JsonObject()
            .Set("a", awkward)
            .Set("list", new List<object> { awkward, new JsonObject().Set(awkward, "key escaped too") }));

        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;
        await Assert.That(root.GetProperty("a").GetString()).IsEqualTo(awkward);
        await Assert.That(root.GetProperty("list")[0].GetString()).IsEqualTo(awkward);
        await Assert.That(root.GetProperty("list")[1].GetProperty(awkward).GetString()).IsEqualTo("key escaped too");
    }

    [Test]
    public async Task EmptyValuesAreOmitted()
    {
        var json = CanonicalJson.Write(new JsonObject()
            .Set("null", null)
            .Set("empty", "")
            .Set("list", new List<object>())
            .Set("kept", "x"));

        await Assert.That(json).IsEqualTo("{\n  \"kept\": \"x\"\n}\n");
    }

    [Test]
    public async Task MembersSortOrdinally()
    {
        var json = CanonicalJson.Write(new JsonObject()
            .Set("b", "1")
            .Set("B", "2")
            .Set("@id", "3")
            .Set("a", "4"));

        await Assert.That(json).IsEqualTo("{\n  \"@id\": \"3\",\n  \"B\": \"2\",\n  \"a\": \"4\",\n  \"b\": \"1\"\n}\n");
    }

    [Test]
    public async Task UnsupportedValueThrows() =>
        await Assert.That(() => CanonicalJson.Write(new JsonObject().Set("a", 1))).Throws<ArgumentException>();
}
