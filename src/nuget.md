Adds an SPDX 3.0.1 software bill of materials to every NuGet package at pack time. Reads
`packages.lock.json` and the local package cache, so it runs offline in milliseconds. A .NET-specific,
drop-in replacement for Microsoft.Sbom.Targets.

```xml
<PropertyGroup>
  <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
</PropertyGroup>
<ItemGroup>
  <PackageReference Include="Sbom" Version="x.y.z" PrivateAssets="all" />
</ItemGroup>
```

See https://github.com/SimonCropp/Sbom
