Packing a net10.0 library with 30 direct `PackageReference`s (179 packages once transitive dependencies are resolved). Median of 5 runs of `dotnet pack --no-build -m:1`, after one warm-up pack; restore and compile excluded.

| | SBOM step | Whole pack | Peak memory of the pack process |
|---|--:|--:|--:|
| No SBOM | – | 790 ms | 109 MB |
| Microsoft.Sbom.Targets 4.1.13 | 1,879 ms | 2,787 ms | 200 MB |
| Sbom | 43 ms | 827 ms | 117 MB |

Sbom's SBOM step is 44x faster, and it adds 8 MB of peak memory to the pack where Microsoft.Sbom.Targets adds 91 MB.

Measured with SDK 10.0.401 on Microsoft Windows 10.0.28000, 16 logical cores, by `BenchmarkTests` in the integration tests.
