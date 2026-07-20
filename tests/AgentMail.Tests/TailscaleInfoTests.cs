using System.Runtime.InteropServices;
using AgentMail;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// Host detection must find the Tailscale CLI even where it isn't on PATH (Windows), so the relay's
/// self-host equals the full MagicDNS name the directory advertises. When it doesn't, a 15-char-truncated
/// NetBIOS fallback (e.g. "eric-aliya-lapt" vs "eric-aliya-laptop") 404s all inbound mail to that host.
/// </summary>
public sealed class TailscaleInfoTests
{
    [Fact]
    public void PATH_is_tried_first()
    {
        Assert.Equal("tailscale", TailscaleInfo.BinaryCandidates().First());
    }

    [Fact]
    public void Candidates_are_non_empty_and_include_an_os_install_path()
    {
        var list = TailscaleInfo.BinaryCandidates().ToList();
        Assert.True(list.Count >= 2);                       // PATH + at least one standard install location
        Assert.All(list, c => Assert.False(string.IsNullOrWhiteSpace(c)));
    }

    [Fact]
    public void Windows_looks_under_program_files_for_tailscale_exe()
    {
        if (!OperatingSystem.IsWindows()) return;           // the fix that matters for the reported bug
        Assert.Contains(TailscaleInfo.BinaryCandidates(),
            c => c.EndsWith("tailscale.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Non_windows_includes_a_conventional_unix_path()
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.Contains(TailscaleInfo.BinaryCandidates(), c => c.StartsWith("/") && c.Contains("tailscale"));
    }
}
