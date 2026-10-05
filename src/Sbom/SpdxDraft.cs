namespace Sbom;

public sealed class SpdxDraft(string text, string prefix)
{
    internal string Text { get; } = text;
    internal string Prefix { get; } = prefix;
}
