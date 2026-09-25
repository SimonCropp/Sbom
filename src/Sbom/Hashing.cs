namespace Sbom;

public static class Hashing
{
    const string digits = "0123456789abcdef";

    public static string Hex(byte[] bytes)
    {
        var chars = new char[bytes.Length * 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = digits[bytes[i] >> 4];
            chars[i * 2 + 1] = digits[bytes[i] & 0xF];
        }

        return new(chars);
    }

    // One instance per thread: element ids alone take a hash each, around a thousand per package, and
    // creating a SHA256 costs more than hashing a short key with it.
    [ThreadStatic]
    static SHA256? sha256;

    static SHA256 Sha256 => sha256 ??= SHA256.Create();

    public static string Sha256Hex(byte[] bytes) =>
        Hex(Sha256.ComputeHash(bytes));

    public static string Sha256Hex(Stream stream) =>
        Hex(Sha256.ComputeHash(stream));

    public static string Sha256Hex(string value) =>
        Sha256Hex(Encoding.UTF8.GetBytes(value));

    /// <summary>
    /// First 8 bytes of SHA-256, as 16 lowercase hex characters. Used for element ids.
    /// </summary>
    public static string ShortHash(string key) =>
        Sha256Hex(key)[..16];

    public static string? Base64ToHex(string? base64)
    {
        if (string.IsNullOrWhiteSpace(base64))
        {
            return null;
        }

        try
        {
            return Hex(Convert.FromBase64String(base64!));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
