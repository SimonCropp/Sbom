public class NupkgWriterTests
{
    [Test]
    public async Task AppendKeepsEveryExistingByte()
    {
        using var temp = new TempDirectory();
        var path = temp.Combine("A.1.0.0.nupkg");
        TestPackage.Create(path, "A", "1.0.0");
        var before = File.ReadAllBytes(path);
        var directoryOffset = DirectoryOffset(before);

        NupkgWriter.Append(path, [new("_manifest/x.json", "{\"a\": 1}"u8.ToArray())]);

        var after = File.ReadAllBytes(path);
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

        using var archive = ZipFile.OpenRead(path);
        await Assert.That(archive.Entries.Count).IsEqualTo(6);
        var entry = archive.GetEntry("_manifest/spdx_3.0/manifest.spdx.json")!;
        using var buffer = new MemoryStream();
        using (var stream = entry.Open())
        {
            stream.CopyTo(buffer);
        }

        await Assert.That(buffer.ToArray().SequenceEqual(content)).IsTrue();
        await Assert.That(entry.Crc32).IsEqualTo(Crc32.Compute(content));

        // Timestamp copied from the nuspec entry.
        var nuspec = archive.GetEntry("A.nuspec")!;
        await Assert.That(entry.LastWriteTime).IsEqualTo(nuspec.LastWriteTime);

        // Every original entry still reads.
        foreach (var original in archive.Entries)
        {
            using var stream = original.Open();
            stream.CopyTo(Stream.Null);
        }
    }

    [Test]
    public async Task ArchiveCommentIsKept()
    {
        using var temp = new TempDirectory();
        var path = temp.Combine("A.1.0.0.nupkg");
        using (var stream = File.Create(path))
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            archive.Comment = "kept";
            archive.CreateEntry("A.nuspec");
        }

        NupkgWriter.Append(path, [new("x.txt", "x"u8.ToArray())]);

        using var read = ZipFile.OpenRead(path);
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
        using (var file = File.Create(path))
        using (var forwardOnly = new ForwardOnlyStream(file))
        using (var archive = new ZipArchive(forwardOnly, ZipArchiveMode.Create))
        {
            using var writer = new StreamWriter(archive.CreateEntry("A.nuspec").Open());
            writer.Write("<package/>");
        }

        NupkgWriter.Append(path, [new("x.txt", "x"u8.ToArray())]);

        using var read = ZipFile.OpenRead(path);
        using var reader = new StreamReader(read.GetEntry("A.nuspec")!.Open());
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
