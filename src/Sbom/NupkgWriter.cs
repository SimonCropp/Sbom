using System.IO.Compression;

namespace Sbom;

public sealed record NewEntry(string Name, byte[] Content);

public sealed class UnsupportedArchiveException(string message) : Exception(message);

/// <summary>
/// Appends entries to a finished zip by writing raw bytes where the central directory starts.
/// Deliberately not ZipArchiveMode.Update: on .NET Framework and .NET 8/9 it rewrites the whole
/// archive, and on .NET 10+ it appends in place but corrupts entries that use data descriptors
/// (dotnet/runtime#126344). Here every byte before the old central directory stays identical, the
/// old directory records are kept verbatim, and only a few KB are written.
/// </summary>
public static class NupkgWriter
{
    const uint localSignature = 0x04034b50;
    const uint centralSignature = 0x02014b50;
    const uint endSignature = 0x06054b50;
    const uint zip64LocatorSignature = 0x07064b50;

    public static void Append(string path, IReadOnlyList<NewEntry> entries)
    {
        using var stream = OpenWithRetry(path);
        Append(stream, entries);
        stream.Flush(true);
    }

    static FileStream OpenWithRetry(string path)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (attempt < 4)
            {
                // A virus scanner commonly holds a freshly written file for a moment.
                Thread.Sleep(100 * attempt);
            }
        }
    }

    public static void Append(Stream stream, IReadOnlyList<NewEntry> entries)
    {
        var end = FindEnd(stream);
        var directory = ReadBytes(stream, end.DirectoryOffset, (int)end.DirectorySize);
        var template = FindTemplate(directory);

        stream.Position = end.DirectoryOffset;
        var originalTail = ReadBytes(stream, end.DirectoryOffset, (int)(stream.Length - end.DirectoryOffset));

        var tail = new MemoryStream();
        var writer = new BinaryWriter(tail);
        var centralRecords = new MemoryStream();
        var central = new BinaryWriter(centralRecords);

        foreach (var entry in entries)
        {
            var name = Encoding.UTF8.GetBytes(entry.Name);
            var compressed = Deflate(entry.Content);
            var crc = Crc32.Compute(entry.Content);
            var localOffset = end.DirectoryOffset + tail.Length;
            if (localOffset > uint.MaxValue)
            {
                throw new UnsupportedArchiveException("The package would need ZIP64 offsets.");
            }

            ushort flags = 0;
            if (name.Any(_ => _ > 0x7F))
            {
                flags = 0x0800;
            }

            writer.Write(localSignature);
            writer.Write((ushort)20);
            writer.Write(flags);
            writer.Write((ushort)8);
            writer.Write(template.Time);
            writer.Write(template.Date);
            writer.Write(crc);
            writer.Write((uint)compressed.Length);
            writer.Write((uint)entry.Content.Length);
            writer.Write((ushort)name.Length);
            writer.Write((ushort)0);
            writer.Write(name);
            writer.Write(compressed);

            central.Write(centralSignature);
            central.Write(template.VersionMadeBy);
            central.Write((ushort)20);
            central.Write(flags);
            central.Write((ushort)8);
            central.Write(template.Time);
            central.Write(template.Date);
            central.Write(crc);
            central.Write((uint)compressed.Length);
            central.Write((uint)entry.Content.Length);
            central.Write((ushort)name.Length);
            central.Write((ushort)0);
            central.Write((ushort)0);
            central.Write((ushort)0);
            central.Write((ushort)0);
            central.Write(template.ExternalAttributes);
            central.Write((uint)localOffset);
            central.Write(name);
        }

        central.Flush();
        var newDirectoryOffset = end.DirectoryOffset + tail.Length;
        var newDirectorySize = directory.Length + centralRecords.Length;
        var newCount = end.EntryCount + entries.Count;
        if (newDirectoryOffset > uint.MaxValue || newCount > ushort.MaxValue)
        {
            throw new UnsupportedArchiveException("The package would need ZIP64 records.");
        }

        writer.Write(directory);
        writer.Write(centralRecords.ToArray());
        writer.Write(endSignature);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)newCount);
        writer.Write((ushort)newCount);
        writer.Write((uint)newDirectorySize);
        writer.Write((uint)newDirectoryOffset);
        writer.Write((ushort)end.Comment.Length);
        writer.Write(end.Comment);
        writer.Flush();

        try
        {
            stream.Position = end.DirectoryOffset;
            tail.Position = 0;
            tail.CopyTo(stream);
            stream.SetLength(end.DirectoryOffset + tail.Length);
        }
        catch
        {
            stream.Position = end.DirectoryOffset;
            stream.Write(originalTail, 0, originalTail.Length);
            stream.SetLength(end.DirectoryOffset + originalTail.Length);
            throw;
        }
    }

    static byte[] Deflate(byte[] content)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflate.Write(content, 0, content.Length);
        }

        return output.ToArray();
    }

    sealed record EndRecord(long DirectoryOffset, uint DirectorySize, int EntryCount, byte[] Comment);

    static EndRecord FindEnd(Stream stream)
    {
        var length = stream.Length;
        var window = (int)Math.Min(length, 22 + ushort.MaxValue);
        var buffer = ReadBytes(stream, length - window, window);
        for (var i = window - 22; i >= 0; i--)
        {
            if (BitConverter.ToUInt32(buffer, i) != endSignature)
            {
                continue;
            }

            var commentLength = BitConverter.ToUInt16(buffer, i + 20);
            if (i + 22 + commentLength != window)
            {
                continue;
            }

            var disk = BitConverter.ToUInt16(buffer, i + 4);
            var directoryDisk = BitConverter.ToUInt16(buffer, i + 6);
            var entriesOnDisk = BitConverter.ToUInt16(buffer, i + 8);
            var entries = BitConverter.ToUInt16(buffer, i + 10);
            var size = BitConverter.ToUInt32(buffer, i + 12);
            var offset = BitConverter.ToUInt32(buffer, i + 16);
            var endOffset = length - window + i;

            if (disk != 0 || directoryDisk != 0 || entriesOnDisk != entries)
            {
                throw new UnsupportedArchiveException("Multi-disk archives are not supported.");
            }

            if (entries == ushort.MaxValue || size == uint.MaxValue || offset == uint.MaxValue)
            {
                throw new UnsupportedArchiveException("ZIP64 archives are not supported.");
            }

            if (i >= 20 && BitConverter.ToUInt32(buffer, i - 20) == zip64LocatorSignature)
            {
                throw new UnsupportedArchiveException("ZIP64 archives are not supported.");
            }

            if (offset + (long)size != endOffset)
            {
                throw new UnsupportedArchiveException("Data between the central directory and its end record.");
            }

            var comment = new byte[commentLength];
            Array.Copy(buffer, i + 22, comment, 0, commentLength);
            return new(offset, size, entries, comment);
        }

        throw new UnsupportedArchiveException("No end of central directory record.");
    }

    sealed record Template(ushort VersionMadeBy, ushort Time, ushort Date, uint ExternalAttributes);

    /// <summary>
    /// New entries copy their timestamp and host attributes from the root .nuspec record, so they
    /// match what NuGet wrote on this OS (and a deterministic pack stays deterministic).
    /// </summary>
    static Template FindTemplate(byte[] directory)
    {
        Template? first = null;
        var position = 0;
        while (position + 46 <= directory.Length)
        {
            if (BitConverter.ToUInt32(directory, position) != centralSignature)
            {
                throw new UnsupportedArchiveException("Malformed central directory.");
            }

            var template = new Template(
                BitConverter.ToUInt16(directory, position + 4),
                BitConverter.ToUInt16(directory, position + 12),
                BitConverter.ToUInt16(directory, position + 14),
                BitConverter.ToUInt32(directory, position + 38));
            first ??= template;
            var nameLength = BitConverter.ToUInt16(directory, position + 28);
            var extraLength = BitConverter.ToUInt16(directory, position + 30);
            var commentLength = BitConverter.ToUInt16(directory, position + 32);
            var name = Encoding.UTF8.GetString(directory, position + 46, nameLength);
            if (!name.Contains('/') &&
                name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))
            {
                return template;
            }

            position += 46 + nameLength + extraLength + commentLength;
        }

        return first ?? new Template(20, 0, 0x21, 0);
    }

    static byte[] ReadBytes(Stream stream, long offset, int count)
    {
        var buffer = new byte[count];
        stream.Position = offset;
        var read = 0;
        while (read < count)
        {
            var chunk = stream.Read(buffer, read, count - read);
            if (chunk == 0)
            {
                throw new UnsupportedArchiveException("Unexpected end of archive.");
            }

            read += chunk;
        }

        return buffer;
    }
}
