public class NupkgWriterTests
{
    [Test]
    public async Task AppendKeepsEveryExistingByte()
    {
        using var temp = new TempDirectory();
        var path = temp.Combine("A.1.0.0.nupkg");
        TestPackage.Create(path, "A", "1.0.0");
        var before = await File.ReadAllBytesAsync(path);
        var directoryOffset = DirectoryOffset(before);

        NupkgWriter.Append(path, [new("_manifest/x.json", "{\"a\": 1}"u8.ToArray())]);

        var after = await File.ReadAllBytesAsync(path);
        await Assert.That(after.Take(directoryOffset).SequenceEqual(before.Take(directoryOffset))).IsTrue();
    }

    [Test]
    public async Task AppendedEntriesReadBack()
    {
        using var temp = new TempDirectory();
        var path = temp.Combine("A.1.0.0.nupkg");
        TestPackage.Create(path, "A", "1.0.0");
        var content = Encoding.UTF8.GetBytes(new string('x', 5000) + "©");

        NupkgWriter.Append(path,
        [
            new("_manifest/spdx_3.0/manifest.spdx.json", content),
            new("_manifest/spdx_3.0/manifest.spdx.json.sha256", "abc"u8.ToArray())
        ]);

        await using var archive = await ZipFile.OpenReadAsync(path);
        await Assert.That(archive.Entries.Count).IsEqualTo(6);
        var entry = archive.GetEntry("_manifest/spdx_3.0/manifest.spdx.json")!;
        using var buffer = new MemoryStream();
        await using (var stream = await entry.OpenAsync())
        {
            await stream.CopyToAsync(buffer);
        }

        await Assert.That(buffer.ToArray().SequenceEqual(content)).IsTrue();
        await Assert.That(entry.Crc32).IsEqualTo(Crc32.Compute(content));

        // Timestamp copied from the nuspec entry.
        var nuspec = archive.GetEntry("A.nuspec")!;
        await Assert.That(entry.LastWriteTime).IsEqualTo(nuspec.LastWriteTime);

        // Every original entry still reads.
        foreach (var original in archive.Entries)
        {
            await using var stream = await original.OpenAsync();
            await stream.CopyToAsync(Stream.Null);
        }
    }

    [Test]
    public async Task ArchiveCommentIsKept()
    {
        using var temp = new TempDirectory();
        var path = temp.Combine("A.1.0.0.nupkg");
        await using (var stream = File.Create(path))
        await using (var archive = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            archive.Comment = "kept";
            archive.CreateEntry("A.nuspec");
        }

        NupkgWriter.Append(path, [new("x.txt", "x"u8.ToArray())]);

        await using var read = await ZipFile.OpenReadAsync(path);
        await Assert.That(read.Comment).IsEqualTo("kept");
        await Assert.That(read.Entries.Count).IsEqualTo(2);
    }

    [Test]
    public async Task DataDescriptorEntriesStayValid()
    {
        // A non-seekable destination forces data descriptors (flag bit 3), the case that
        // ZipArchiveMode.Update corrupts on .NET 10.
        using var temp = new TempDirectory();
        var path = temp.Combine("A.1.0.0.nupkg");
        await using (var file = File.Create(path))
        await using (var forwardOnly = new ForwardOnlyStream(file))
        await using (var archive = new ZipArchive(forwardOnly, ZipArchiveMode.Create))
        {
            await using var writer = new StreamWriter(await archive.CreateEntry("A.nuspec").OpenAsync());
            await writer.WriteAsync("<package/>");
        }

        NupkgWriter.Append(path, [new("x.txt", "x"u8.ToArray())]);

        await using var read = await ZipFile.OpenReadAsync(path);
        using var reader = new StreamReader(await read.GetEntry("A.nuspec")!.OpenAsync());
        await Assert.That(await reader.ReadToEndAsync()).IsEqualTo("<package/>");
    }

    [Test]
    public async Task NotAZipThrows()
    {
        using var temp = new TempDirectory();
        var path = temp.Write("A.nupkg", "not a zip");
        await Assert.That(() => NupkgWriter.Append(path, [new("x", [1])])).Throws<UnsupportedArchiveException>();
    }

    static int DirectoryOffset(byte[] bytes)
    {
        for (var i = bytes.Length - 22; i >= 0; i--)
        {
            if (BitConverter.ToUInt32(bytes, i) == 0x06054b50)
            {
                return (int)BitConverter.ToUInt32(bytes, i + 16);
            }
        }

        throw new("No end record");
    }

    [Test]
    public async Task FailedWriteRestoresTheOriginalBytes()
    {
        using var temp = new TempDirectory();
        var path = temp.Combine("A.1.0.0.nupkg");
        TestPackage.Create(path, "A", "1.0.0");
        var before = File.ReadAllBytes(path);

        using var memory = new MemoryStream();
        memory.Write(before);
        using var failing = new FailOnceStream(memory);

        await Assert.That(() => NupkgWriter.Append(failing, [new("x.txt", new byte[10_000])])).Throws<IOException>();
        await Assert.That(memory.ToArray().SequenceEqual(before)).IsTrue();

        // Still a readable package.
        using var archive = new ZipArchive(new MemoryStream(memory.ToArray()), ZipArchiveMode.Read);
        await Assert.That(archive.Entries.Count).IsEqualTo(4);
    }

    [Test]
    public async Task Zip64Throws()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            for (var i = 0; i < ushort.MaxValue + 1; i++)
            {
                archive.CreateEntry($"{i}.txt", CompressionLevel.NoCompression);
            }
        }

        await Assert.That(() => NupkgWriter.Append(stream, [new("x", [1])])).Throws<UnsupportedArchiveException>();
    }

    /// <summary>
    /// Throws on the first write, then behaves: the first write is the new tail, the second is the
    /// rollback.
    /// </summary>
    sealed class FailOnceStream(Stream inner) : Stream
    {
        bool failed;
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!failed)
            {
                failed = true;
                // A partial write, the realistic failure: disk full part way through.
                inner.Write(buffer, offset, count / 2);
                throw new IOException("Disk full");
            }

            inner.Write(buffer, offset, count);
        }
    }

    sealed class ForwardOnlyStream(Stream inner) : Stream
    {
        long position;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => position;
            set => throw new NotSupportedException();
        }

        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            inner.Write(buffer, offset, count);
            position += count;
        }
    }
}
