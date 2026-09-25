namespace Sbom.IntegrationTests;

public static class DotnetCliRunner
{
    public static async Task<CliResult> Run(
        string command,
        string projectPath,
        IReadOnlyDictionary<string, string>? properties = null,
        string? workingDirectory = null,
        string? packagesDirectory = null,
        string verbosity = "minimal",
        IReadOnlyList<string>? arguments = null,
        Cancel cancellation = default)
    {
        var info = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Path.GetDirectoryName(Path.GetFullPath(projectPath))!
        };
        info.Environment["DOTNET_NOLOGO"] = "true";
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "true";
        if (packagesDirectory != null)
        {
            // Without an isolated package directory the global cache serves a previously restored
            // build of the same version, and a rebuilt package silently never reaches the fixture.
            info.Environment["NUGET_PACKAGES"] = packagesDirectory;
        }

        info.ArgumentList.Add(command);
        info.ArgumentList.Add(projectPath);
        info.ArgumentList.Add("--nologo");
        info.ArgumentList.Add("--verbosity");
        info.ArgumentList.Add(verbosity);
        if (arguments != null)
        {
            foreach (var argument in arguments)
            {
                info.ArgumentList.Add(argument);
            }
        }

        if (properties != null)
        {
            foreach (var property in properties)
            {
                info.ArgumentList.Add($"-p:{property.Key}={property.Value}");
            }
        }

        using var process = Process.Start(info) ??
                            throw new("Could not start dotnet.");
        var stdout = process.StandardOutput.ReadToEndAsync(cancellation);
        var stderr = process.StandardError.ReadToEndAsync(cancellation);
        await process.WaitForExitAsync(cancellation);
        return new(process.ExitCode, await stdout, await stderr);
    }

    /// <summary>
    /// Resolved in the given directory, because SDK selection depends on the global.json in scope
    /// there. Asking in the repo and then building somewhere else can answer about a different SDK
    /// than the one that runs the build.
    /// </summary>
    public static string SdkVersion(string workingDirectory)
    {
        var info = new ProcessStartInfo("dotnet", "--version")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory
        };
        using var process = Process.Start(info)!;
        var version = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        return version;
    }
}
