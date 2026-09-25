namespace Sbom;

/// <summary>
/// Writes a tree of <see cref="JsonObject"/>, <see cref="List{T}"/> and string values in one
/// canonical form: members sorted ordinally, two-space indent, "\n" newlines, UTF-8, and only the
/// escapes JSON requires. System.Text.Json's encoder escapes '+', '©' and HTML characters, and its
/// newline follows the platform, so it cannot produce byte-identical output across hosts.
/// </summary>
public sealed class JsonObject : SortedDictionary<string, object>
{
    public JsonObject() : base(StringComparer.Ordinal)
    {
    }

    /// <summary>
    /// Adds the member unless the value is null or empty. Absent is the SPDX 3 way of saying
    /// "no assertion".
    /// </summary>
    public JsonObject Set(string name, object? value)
    {
        switch (value)
        {
            case null:
                return this;
            case string {Length: 0}:
                return this;
            case List<object> {Count: 0}:
                return this;
        }

        this[name] = value;
        return this;
    }
}

public static class CanonicalJson
{
    public static string Write(object value)
    {
        var builder = new StringBuilder();
        Write(builder, value, 0);
        builder.Append('\n');
        return builder.ToString();
    }

    static void Write(StringBuilder builder, object value, int depth)
    {
        switch (value)
        {
            case string text:
                WriteString(builder, text);
                return;
            case JsonObject obj:
                WriteObject(builder, obj, depth);
                return;
            case List<object> list:
                WriteArray(builder, list, depth);
                return;
        }

        throw new ArgumentException($"Unsupported JSON value: {value.GetType()}");
    }

    static void WriteObject(StringBuilder builder, JsonObject obj, int depth)
    {
        builder.Append('{');
        var first = true;
        foreach (var pair in obj)
        {
            if (!first)
            {
                builder.Append(',');
            }

            first = false;
            builder.Append('\n');
            Indent(builder, depth + 1);
            WriteString(builder, pair.Key);
            builder.Append(": ");
            Write(builder, pair.Value, depth + 1);
        }

        builder.Append('\n');
        Indent(builder, depth);
        builder.Append('}');
    }

    static void WriteArray(StringBuilder builder, List<object> list, int depth)
    {
        builder.Append('[');
        var first = true;
        foreach (var item in list)
        {
            if (!first)
            {
                builder.Append(',');
            }

            first = false;
            builder.Append('\n');
            Indent(builder, depth + 1);
            Write(builder, item, depth + 1);
        }

        builder.Append('\n');
        Indent(builder, depth);
        builder.Append(']');
    }

    static void Indent(StringBuilder builder, int depth) =>
        builder.Append(' ', depth * 2);

    static void WriteString(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach (var ch in value)
        {
            switch (ch)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (ch < 0x20)
                    {
                        builder.Append("\\u");
                        builder.Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                        break;
                    }

                    builder.Append(ch);
                    break;
            }
        }

        builder.Append('"');
    }
}
