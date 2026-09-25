Adds an SPDX 3.0.1 software bill of materials to every NuGet package at pack time. Reads
the restore graph and the local package cache, so it runs offline in milliseconds. A .NET-specific,
drop-in replacement for Microsoft.Sbom.Targets.

```xml
<PackageReference Include="Sbom" Version="x.y.z" PrivateAssets="all" />
```

See https://github.com/SimonCropp/Sbom
