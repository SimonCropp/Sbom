public static class ModuleInitializer
{
    [ModuleInitializer]
    public static void Init()
    {
        VerifyDiffPlex.Initialize(OutputType.Compact);
        // BuildEventArgs carries a lot that says nothing about the diagnostic: a timestamp, the
        // thread it was raised on, the sender. Stripping them leaves a snapshot of just the code and
        // the message, which is the part worth reviewing in a diff.
        VerifierSettings.IgnoreMembers(
            "HelpKeyword",
            "SenderName",
            "ContinueOnError",
            "ProjectFileOfTaskNode",
            "File",
            "Subcategory",
            "Timestamp",
            "BuildEventContext",
            "Importance");
        VerifierSettings.IgnoreMember<BuildEventArgs>(_ => _.ThreadId);
        VerifierSettings.Inline(maxLines: 10, applyMaxLinesToExisting: true);
    }
}
