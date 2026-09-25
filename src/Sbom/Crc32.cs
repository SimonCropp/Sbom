namespace Sbom;

/// <summary>
/// Table-driven CRC-32 (IEEE 802.3), as zip requires. Avoids shipping System.IO.Hashing.
/// </summary>
public static class Crc32
{
    static readonly uint[] table = BuildTable();

    static uint[] BuildTable()
    {
        var result = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var value = i;
            for (var bit = 0; bit < 8; bit++)
            {
                if ((value & 1) == 1)
                {
                    value = 0xEDB88320u ^ (value >> 1);
                    continue;
                }

                value >>= 1;
            }

            result[i] = value;
        }

        return result;
    }

    public static uint Compute(byte[] data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data)
        {
            crc = table[(crc ^ value) & 0xFF] ^ (crc >> 8);
        }

        return ~crc;
    }
}
