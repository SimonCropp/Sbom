namespace Sbom;

/// <summary>
/// A small JSON parser, enough for packages.lock.json. Objects become <see cref="JsonObject"/>,
/// arrays <see cref="List{T}"/>, strings and numbers <see cref="string"/>, booleans
/// <see cref="bool"/>, and null <c>null</c>. It replaces System.Text.Json, which on netstandard2.0
/// meant shipping nine assemblies alongside the task and loading them into every build.
/// </summary>
public sealed class JsonReader
{
    readonly string text;
    int position;

    JsonReader(string text) =>
        this.text = text;

    public static object? Parse(string text)
    {
        var reader = new JsonReader(text);
        reader.SkipWhitespace();
        var value = reader.ReadValue();
        reader.SkipWhitespace();
        if (reader.position != text.Length)
        {
            throw reader.Error("Unexpected content after the root value");
        }

        return value;
    }

    object? ReadValue()
    {
        if (position >= text.Length)
        {
            throw Error("Unexpected end of JSON");
        }

        var ch = text[position];
        switch (ch)
        {
            case '{':
                return ReadObject();
            case '[':
                return ReadArray();
            case '"':
                return ReadString();
            case 't':
                Expect("true");
                return true;
            case 'f':
                Expect("false");
                return false;
            case 'n':
                Expect("null");
                return null;
        }

        if (ch == '-' || char.IsDigit(ch))
        {
            return ReadNumber();
        }

        throw Error($"Unexpected character '{ch}'");
    }

    JsonObject ReadObject()
    {
        position++;
        var result = new JsonObject();
        SkipWhitespace();
        if (Peek() == '}')
        {
            position++;
            return result;
        }

        while (true)
        {
            SkipWhitespace();
            if (Peek() != '"')
            {
                throw Error("Expected a property name");
            }

            var name = ReadString();
            SkipWhitespace();
            if (Peek() != ':')
            {
                throw Error("Expected ':'");
            }

            position++;
            SkipWhitespace();
            result[name] = ReadValue()!;
            SkipWhitespace();
            var next = Peek();
            position++;
            if (next == ',')
            {
                continue;
            }

            if (next == '}')
            {
                return result;
            }

            throw Error("Expected ',' or '}'");
        }
    }

    List<object?> ReadArray()
    {
        position++;
        var result = new List<object?>();
        SkipWhitespace();
        if (Peek() == ']')
        {
            position++;
            return result;
        }

        while (true)
        {
            SkipWhitespace();
            result.Add(ReadValue());
            SkipWhitespace();
            var next = Peek();
            position++;
            if (next == ',')
            {
                continue;
            }

            if (next == ']')
            {
                return result;
            }

            throw Error("Expected ',' or ']'");
        }
    }

    string ReadString()
    {
        position++;
        var start = position;
        // Fast path: no escapes, the common case for every key and value in a lock file.
        while (position < text.Length)
        {
            var ch = text[position];
            if (ch == '"')
            {
                var value = text.Substring(start, position - start);
                position++;
                return value;
            }

            if (ch == '\\')
            {
                break;
            }

            position++;
        }

        var builder = new StringBuilder(text, start, position - start, position - start + 16);
        while (position < text.Length)
        {
            var ch = text[position++];
            if (ch == '"')
            {
                return builder.ToString();
            }

            if (ch != '\\')
            {
                builder.Append(ch);
                continue;
            }

            if (position >= text.Length)
            {
                break;
            }

            var escape = text[position++];
            switch (escape)
            {
                case '"':
                case '\\':
                case '/':
                    builder.Append(escape);
                    break;
                case 'b':
                    builder.Append('\b');
                    break;
                case 'f':
                    builder.Append('\f');
                    break;
                case 'n':
                    builder.Append('\n');
                    break;
                case 'r':
                    builder.Append('\r');
                    break;
                case 't':
                    builder.Append('\t');
                    break;
                case 'u':
                    if (position + 4 > text.Length)
                    {
                        throw Error("Truncated \\u escape");
                    }

                    builder.Append((char)int.Parse(text.Substring(position, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                    position += 4;
                    break;
                default:
                    throw Error($"Invalid escape '\\{escape}'");
            }
        }

        throw Error("Unterminated string");
    }

    string ReadNumber()
    {
        var start = position;
        while (position < text.Length &&
               "+-0123456789.eE".IndexOf(text[position]) >= 0)
        {
            position++;
        }

        return text.Substring(start, position - start);
    }

    void Expect(string literal)
    {
        if (string.CompareOrdinal(text, position, literal, 0, literal.Length) != 0)
        {
            throw Error($"Expected '{literal}'");
        }

        position += literal.Length;
    }

    char Peek()
    {
        if (position >= text.Length)
        {
            throw Error("Unexpected end of JSON");
        }

        return text[position];
    }

    void SkipWhitespace()
    {
        while (position < text.Length &&
               text[position] is ' ' or '\t' or '\n' or '\r')
        {
            position++;
        }
    }

    FormatException Error(string message) =>
        new($"{message} at offset {position}.");
}
