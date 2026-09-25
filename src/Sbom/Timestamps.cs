namespace Sbom;

public static class Timestamps
{
    /// <summary>
    /// DeterministicTimestamp (NuGet's own reproducible-pack knob) wins, then SOURCE_DATE_EPOCH, then
    /// the clock. Always UTC, whole seconds.
    /// </summary>
    public static DateTimeOffset Resolve(string? deterministicTimestamp, string? sourceDateEpoch, Func<DateTimeOffset> now)
    {
        if (TryParse(deterministicTimestamp, out var value) ||
            TryParse(sourceDateEpoch, out value))
        {
            return value;
        }

        return Truncate(now());
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
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
