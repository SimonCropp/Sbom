/// <summary>
/// Compares Sbom with Microsoft.Sbom.Targets on a package with a realistic dependency load, and
/// writes the results to docs/benchmark.include.md, which MarkdownSnippets pulls into the readme.
/// Explicit: it takes minutes, needs nuget.org, and its numbers depend on the machine.
/// </summary>
public class BenchmarkTests
{
    const string fixture = "Benchmark.Large";
    const string project = "Benchmark.Large.csproj";
    const int runs = 5;

    enum Mode
    {
        None,
        Microsoft,
        Sbom
    }

    sealed record Sample(long PackMs, long SbomMs, long PeakBytes);

    sealed record Summary(Mode Mode, long PackMs, long SbomMs, long PeakBytes);

    [Test]
    [Explicit]
    public async Task CompareWithMicrosoftSbomTargets()
    {
        var summaries = new List<Summary>();
        int? dependencyCount = null;
        foreach (var mode in Enum.GetValues<Mode>())
        {
            var work = AuthorPack.Prepare(fixture, $"Benchmark{mode}");
            var properties = Properties(mode);

            // Restore and build up front, so the measured runs are pack only: no network, no compile.
            var build = await DotnetCliRunner.Run(
                "build",
                Path.Combine(work, project),
                properties,
                workingDirectory: work,
                packagesDirectory: AuthorPack.PackagesDirectory,
                arguments: ["--configuration", "Release", "--disable-build-servers"]);
            await Assert.That(build.ExitCode).IsEqualTo(0).Because(build.Combined);

            dependencyCount ??= CountLockedPackages(Path.Combine(work, "packages.lock.json"));

            // One unmeasured pack, so JIT and file cache warm-up are not charged to either generator.
            await Pack(work, properties, mode);
            var samples = new List<Sample>();
            for (var i = 0; i < runs; i++)
            {
                samples.Add(await Pack(work, properties, mode));
            }

            summaries.Add(new(
                mode,
                Median(samples.Select(_ => _.PackMs)),
                Median(samples.Select(_ => _.SbomMs)),
                Median(samples.Select(_ => _.PeakBytes))));
        }

        var markdown = Render(summaries, dependencyCount ?? 0);
        await File.WriteAllTextAsync(Path.Combine(TestEnvironment.RepoRoot, "docs", "benchmark.include.md"), markdown);
        Console.WriteLine(markdown);
    }

    static Dictionary<string, string> Properties(Mode mode) =>
        new()
        {
            ["BenchmarkMode"] = mode.ToString(),
            ["SbomVersion"] = PackageUnderTest.Ensure().Version
        };

    /// <summary>
    /// A single-process pack (-m:1, no node reuse), so the sampled process holds the whole build,
    /// including whichever SBOM generator runs inside it.
    /// </summary>
    static async Task<Sample> Pack(string work, Dictionary<string, string> properties, Mode mode)
    {
        var output = Path.Combine(work, "out");
        if (Directory.Exists(output))
        {
            // A fresh package every run. Otherwise GenerateNuspec is skipped as up to date and the
            // generators see a package that already carries an SBOM.
            Directory.Delete(output, true);
        }

        // Sbom skips generation when none of its inputs changed. Deleting the stamp makes it
        // generate every time, as Microsoft.Sbom.Targets does, so the two measure the same work.
        var stamp = Path.Combine(work, "obj", "Release", "sbom", "sbom.stamp");
        if (File.Exists(stamp))
        {
            File.Delete(stamp);
        }

        var info = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = work,
            Environment =
            {
                ["DOTNET_NOLOGO"] = "true",
                ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "true",
                ["NUGET_PACKAGES"] = AuthorPack.PackagesDirectory,
                ["MSBUILDDISABLENODEREUSE"] = "1"
            }
        };
        foreach (var argument in new[]
                 {
                     "pack", Path.Combine(work, project), "--no-build", "--configuration", "Release",
                     "--output", output, "--disable-build-servers", "-m:1", "-clp:PerformanceSummary"
                 })
        {
            info.ArgumentList.Add(argument);
        }

        foreach (var property in properties)
        {
            info.ArgumentList.Add($"-p:{property.Key}={property.Value}");
        }

        var stopwatch = Stopwatch.StartNew();
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        long peak = 0;
        while (!process.HasExited)
        {
            try
            {
                process.Refresh();
                peak = Math.Max(peak, process.PeakWorkingSet64);
            }
            catch (InvalidOperationException)
            {
                // Exited between the check and the read.
            }

            await Task.Delay(20);
        }

        await process.WaitForExitAsync();
        stopwatch.Stop();
        var log = await stdout + await stderr;
        if (process.ExitCode != 0)
        {
            throw new($"Pack failed ({mode}):{Environment.NewLine}{log}");
        }

        // Every target each generator adds, so neither is charged less than it costs.
        string[] sbomTargets = mode switch
        {
            Mode.Microsoft => ["GenerateSbomTarget"],
            Mode.Sbom => ["_Sbom_AddToPackage", "_Sbom_Prepare", "SbomGenerate", "_Sbom_GetReferences"],
            _ => []
        };
        var sbomMs = sbomTargets.Sum(_ => TargetMilliseconds(log, _));

        return new(stopwatch.ElapsedMilliseconds, sbomMs, peak);
    }

    /// <summary>
    /// Reads a target's time from the "Target Performance Summary" that -clp:PerformanceSummary
    /// prints, e.g. "     7836 ms  GenerateSbomTarget      1 calls".
    /// </summary>
    static long TargetMilliseconds(string log, string target)
    {
        var match = Regex.Match(log, $@"^\s*(\d+) ms\s+{Regex.Escape(target)}\s+\d+ calls", RegexOptions.Multiline);
        if (!match.Success)
        {
            throw new($"{target} missing from the performance summary:{Environment.NewLine}{log}");
        }

        return long.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
    }

    static int CountLockedPackages(string lockFile)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(lockFile));
        return document.RootElement.GetProperty("dependencies")
            .EnumerateObject()
            .Where(_ => !_.Name.Contains('/'))
            .SelectMany(_ => _.Value.EnumerateObject())
            .Select(_ => _.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
    }

    static long Median(IEnumerable<long> values)
    {
        var sorted = values.Order().ToList();
        return sorted[sorted.Count / 2];
    }

    static string Render(List<Summary> summaries, int dependencyCount)
    {
        var none = summaries.Single(_ => _.Mode == Mode.None);
        var microsoft = summaries.Single(_ => _.Mode == Mode.Microsoft);
        var sbom = summaries.Single(_ => _.Mode == Mode.Sbom);

        static string Mb(long bytes) => (bytes / 1024d / 1024d).ToString("N0", CultureInfo.InvariantCulture);
        static string Ms(long ms) => ms.ToString("N0", CultureInfo.InvariantCulture);

        var sdk = DotnetCliRunner.SdkVersion(Path.Combine(TestEnvironment.RepoRoot, "IntegrationTests"));
        var builder = new StringBuilder();
        builder.AppendLine($"Packing a net10.0 library with 30 direct `PackageReference`s ({dependencyCount} packages once transitive dependencies are resolved). Median of {runs} runs of `dotnet pack --no-build -m:1`, after one warm-up pack; restore and compile excluded.");
        builder.AppendLine();
        builder.AppendLine("| | SBOM step | Whole pack | Peak memory of the pack process |");
        builder.AppendLine("|---|--:|--:|--:|");
        builder.AppendLine($"| No SBOM | – | {Ms(none.PackMs)} ms | {Mb(none.PeakBytes)} MB |");
        builder.AppendLine($"| Microsoft.Sbom.Targets 4.1.13 | {Ms(microsoft.SbomMs)} ms | {Ms(microsoft.PackMs)} ms | {Mb(microsoft.PeakBytes)} MB |");
        builder.AppendLine($"| Sbom | {Ms(sbom.SbomMs)} ms | {Ms(sbom.PackMs)} ms | {Mb(sbom.PeakBytes)} MB |");
        builder.AppendLine();
        builder.AppendLine($"Sbom's SBOM step is {Ratio(microsoft.SbomMs, sbom.SbomMs)}x faster, and it adds {Mb(Math.Max(0, sbom.PeakBytes - none.PeakBytes))} MB of peak memory to the pack where Microsoft.Sbom.Targets adds {Mb(Math.Max(0, microsoft.PeakBytes - none.PeakBytes))} MB.");
        builder.AppendLine();
        builder.AppendLine($"Measured with SDK {sdk} on {RuntimeInformation.OSDescription.Trim()}, {Environment.ProcessorCount} logical cores, by `BenchmarkTests` in the integration tests.");
        return builder.ToString();
    }

    static string Ratio(long slow, long fast) =>
        (slow / (double)Math.Max(1, fast)).ToString("N0", CultureInfo.InvariantCulture);
}
