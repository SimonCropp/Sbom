using System.Security.Cryptography;

namespace Sbom;

public static class Hashing
{
    public static string Hex(byte[] bytes)
    {
        var builder = new StringBuilder(bytes.Length * 2);
        foreach (var value in bytes)
        {
            builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    public static string Sha256Hex(byte[] bytes)
    {
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(bytes));
    }

    public static string Sha256Hex(Stream stream)
    {
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(stream));
    }

    public static string Sha256Hex(string value) =>
        Sha256Hex(Encoding.UTF8.GetBytes(value));

    /// <summary>
    /// First 8 bytes of SHA-256, as 16 lowercase hex characters. Used for element ids.
    /// </summary>
    public static string ShortHash(string key) =>
        Sha256Hex(key).Substring(0, 16);

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
