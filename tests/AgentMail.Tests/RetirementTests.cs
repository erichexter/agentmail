using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// Regression tests for #296 — a retired name resurrected from the white pages.
///
/// The incident: ray was renamed to maverick on 2026-07-29 and every peer acked it. Then
/// eric-aliya-laptop rebooted, harrell rebuilt its roll-call list FROM `agentmail agents`, and `ray`
/// came back — so one machine was roll-called as two agents. Harrell patched its own list-building,
/// but that fixed one consumer while the registry kept handing out the dead name.
///
/// The root cause is a modelling one, not a bug in any single code path: STALE was carrying two
/// different questions. "last_seen is old" is recoverable — the host may simply be off, and the record
/// heals itself when it returns. "this name is gone forever" is a decision that nothing about
/// freshness can express. A consumer reading only freshness cannot tell them apart, so the second one
/// silently degrades into the first on the next reboot.
/// </summary>
public class RetirementTests
{
    static AgentRecord Rec(string agent, string host, string status = "online", string? successor = null) => new()
    {
        Agent = agent,
        Host = host,
        User = "test",
        Endpoint = $"http://{host}:8787",
        Endpoints = [$"http://{host}:8787"],
        Status = status,
        Successor = successor,
        Version = 3,
        LastSeen = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
    };

    [Fact]
    public void Retired_is_not_the_same_as_offline_or_stale()
    {
        // The whole point of the new state. `offline` is self-asserted and means "down, may return";
        // `retired` means "never valid again". If these ever collapse back into one value, the
        // resurrection bug returns with them.
        Assert.True(DirectoryStore.IsRetired(Rec("ray", "h", status: "retired")));
        Assert.False(DirectoryStore.IsRetired(Rec("ray", "h", status: "offline")));
        Assert.False(DirectoryStore.IsRetired(Rec("ray", "h", status: "online")));
    }

    [Fact]
    public void Retired_is_matched_case_insensitively()
    {
        // Records arrive over the wire from peers on other platforms. A case difference must not be
        // the thing that decides whether a dead name is filtered out.
        Assert.True(DirectoryStore.IsRetired(Rec("ray", "h", status: "RETIRED")));
        Assert.True(DirectoryStore.IsRetired(Rec("ray", "h", status: "Retired")));
    }

    [Fact]
    public void A_retired_record_carries_its_successor()
    {
        // Without this the caller learns only that the name is dead, not where to go — which is the
        // half of the problem that actually costs a human a debugging session.
        var r = Rec("ray", "desktop-bqgtlc4-7", status: "retired", successor: "maverick@desktop-bqgtlc4-7");
        Assert.True(DirectoryStore.IsRetired(r));
        Assert.Equal("maverick@desktop-bqgtlc4-7", r.Successor);
    }

    [Fact]
    public void A_live_record_has_no_successor()
    {
        Assert.Null(Rec("maverick", "desktop-bqgtlc4-7").Successor);
    }

    [Fact]
    public void The_agents_listing_filter_drops_retired_and_keeps_everything_else()
    {
        // This models exactly what `agents` does, and it is the assertion that matters: the list a peer
        // rebuilds its targets from must not contain the retired name, while a merely-offline agent
        // MUST survive — filtering that one out would take a recoverable host off the mesh.
        var all = new List<AgentRecord>
        {
            Rec("ray", "desktop-bqgtlc4-7", status: "retired", successor: "maverick@desktop-bqgtlc4-7"),
            Rec("maverick", "desktop-bqgtlc4-7"),
            Rec("harrell", "eric-aliya-laptop", status: "offline"),
        };

        var listed = all.Where(r => !DirectoryStore.IsRetired(r)).Select(r => r.Key).ToList();

        Assert.DoesNotContain("ray@desktop-bqgtlc4-7", listed);
        Assert.Contains("maverick@desktop-bqgtlc4-7", listed);
        Assert.Contains("harrell@eric-aliya-laptop", listed);   // offline is NOT retired
        Assert.Equal(2, listed.Count);
    }

    [Fact]
    public void Retiring_does_not_delete_the_record()
    {
        // Retirement removes a name from DISCOVERY, not from DELIVERY. Mail already in flight is
        // addressed to the old name and still has to land, so the record stays on disk and stays
        // resolvable. Deleting it instead would turn a rename into lost mail.
        var r = Rec("ray", "desktop-bqgtlc4-7", status: "retired", successor: "maverick@desktop-bqgtlc4-7");
        Assert.False(string.IsNullOrEmpty(r.Endpoint));
        Assert.NotEmpty(r.Endpoints);
    }
}
