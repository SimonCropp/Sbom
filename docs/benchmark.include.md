Packing a net10.0 library with 30 direct `PackageReference`s (179 packages once transitive dependencies are resolved). Median of 5 runs of `dotnet pack --no-build -m:1`, after one warm-up pack; restore and compile excluded.

| | SBOM step | Whole pack | Peak memory of the pack process |
|---|--:|--:|--:|
| No SBOM | – | 745 ms | 113 MB |
| Microsoft.Sbom.Targets 4.1.13 | 1,630 ms | 2,373 ms | 200 MB |
| Sbom | 48 ms | 780 ms | 117 MB |

Sbom's is 34x faster, and it adds 5 MB of peak memory to the pack where Microsoft.Sbom.Targets adds 87 MB.

Measured with SDK 10.0.401 on Microsoft Windows 10.0.28000, 16 logical cores, by `BenchmarkTests` in the integration tests.
