# Contributing

## Build and test

```
dotnet build src --configuration Release
dotnet run --project src/Sbom.Tests --configuration Release --no-build -- --no-ansi --progress off
```

The integration suite consumes the packages the Release build emits into `nugets`, so it runs second:

```
dotnet build IntegrationTests --configuration Release
dotnet run --project IntegrationTests/IntegrationTests --configuration Release --no-build -- --no-ansi --progress off
```

## Snapshots

Verify inlines snapshots under ten lines into the test source. A failing snapshot prints the received
value; accept it by pasting into the `.Snapshot(...)` call, or open the diff tool.

## Docs

`readme.md` and `docs/*.md` are maintained in place by MarkdownSnippets, which runs on any build of
`src/Sbom.Tests`. Edit the prose directly, but never the content between `<!-- snippet: -->` and
`<!-- endSnippet -->`.
