namespace Sbom;

public static class Timestamps
{
    /// <summary>
    /// DeterministicTimestamp (NuGet's own reproducible-pack knob) wins, then SOURCE_DATE_EPOCH, then
    /// the clock. Always UTC, whole seconds.
    /// </summary>
    public static DateTimeOffset Resolve(string? deterministicTimestamp, string? sourceDateEpoch, Func<DateTimeOffset> now)
    {
        var value = Explicit(deterministicTimestamp, sourceDateEpoch);
        if (value != null)
        {
            return value.Value;
        }

        return Truncate(now());
    }

    /// <summary>
    /// The timestamp the build asked for, or null when it is left to the clock.
    /// </summary>
    public static DateTimeOffset? Explicit(string? deterministicTimestamp, string? sourceDateEpoch)
    {
        if (TryParse(deterministicTimestamp, out var value) ||
            TryParse(sourceDateEpoch, out value))
        {
            return value;
        }

        return null;
    }

    const string createdFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    const string createdProperty = "\"created\": \"";

    /// <summary>
    /// The created timestamp of a manifest this tool wrote, which has exactly one.
    /// </summary>
    public static DateTimeOffset? ReadCreated(string manifest)
    {
        var start = manifest.IndexOf(createdProperty, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        start += createdProperty.Length;
        var end = manifest.IndexOf('"', start);
        if (end < 0 ||
            !DateTimeOffset.TryParseExact(
                manifest.Substring(start, end - start),
                createdFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var value))
        {
            return null;
        }

        return value;
    }

    static bool TryParse(string? text, out DateTimeOffset value)
    {
        value = default;
        if (text == null)
        {
            return false;
        }

        text = text.Trim();
        if (text.Length == 0)
        {
            return false;
        }

        if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
        {
            value = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }

        // NuGet also accepts true/false as modes here. Neither is a point in time, and neither parses.
        if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
        {
            value = Truncate(parsed);
            return true;
        }

        return false;
    }

    static DateTimeOffset Truncate(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new(utc.Ticks - utc.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
    }

    public static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString(createdFormat, CultureInfo.InvariantCulture);
}
