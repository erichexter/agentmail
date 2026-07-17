using System.Runtime.CompilerServices;

namespace AgentMail.Tests;

/// <summary>
/// Points AGENTMAIL_ROOT at a throwaway directory before ANY test — or any type that reads Paths.Root — runs.
///
/// This has to be a module initializer, not per-test setup. Paths.Root is resolved once on first access and
/// cached for the process, so setting the variable in a constructor only works if that constructor happens to
/// win the race against the first read. It did, which is worse than failing: the suite would have started
/// writing real Ed25519 identities into the live ~/.claude/agentmail/keys the moment test ordering shifted.
/// </summary>
static class TestRoot
{
    public static string Path { get; private set; } = "";

    [ModuleInitializer]
    internal static void Init()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "agentmail-tests", Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("AGENTMAIL_ROOT", Path);
        Directory.CreateDirectory(Path);

        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); } catch { }
        };
    }
}
