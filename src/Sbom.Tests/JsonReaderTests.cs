public class JsonReaderTests
{
    [Test]
    public async Task ParsesEveryValueKind()
    {
        var root = (JsonObject)JsonReader.Parse(
            """
            {
              "string": "a\"b\\c\/d\n\té",
              "number": -1.5e3,
              "true": true,
              "false": false,
              "null": null,
              "array": [1, "two", {}, []],
              "object": {"nested": {}}
            }
            """)!;

        await Assert.That(root["string"]).IsEqualTo("a\"b\\c/d\n\té");
        await Assert.That(root["number"]).IsEqualTo("-1.5e3");
        await Assert.That((bool)root["true"]).IsTrue();
        await Assert.That((bool)root["false"]).IsFalse();
        await Assert.That(root["null"]).IsNull();
        var array = (List<object?>)root["array"];
        await Assert.That(array.Count).IsEqualTo(4);
        await Assert.That(array[1]).IsEqualTo("two");
        await Assert.That(((JsonObject)root["object"])["nested"]).IsTypeOf<JsonObject>();
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("{\"a\" 1}")]
    [Arguments("{\"a\": 1,}")]
    [Arguments("[1 2]")]
    [Arguments("\"unterminated")]
    [Arguments("\"bad \\x escape\"")]
    [Arguments("{} trailing")]
    [Arguments("tru")]
    public async Task RejectsMalformedJson(string json) =>
        await Assert.That(() => JsonReader.Parse(json)).Throws<FormatException>();

    [Test]
    public async Task MalformedLockFileFailsLoudly() =>
        await Assert.That(() => LockFile.ReadText("{\"dependencies\": {")).Throws<FormatException>();

    [Test]
    public async Task LockFileWithoutDependenciesIsEmpty() =>
        await Assert.That(LockFile.ReadText("{\"version\": 2}")).IsEmpty();
}
