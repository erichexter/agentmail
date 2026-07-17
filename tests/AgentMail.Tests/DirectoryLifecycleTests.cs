using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// Regression tests for #8 — the directory-lifecycle bug that took wolf@windev2407eval off the mesh on
/// 2026-07-17 at 24.2h and made his inbound flap 202/404 on a ~60s cycle.
///
/// These reproduce the incident's mechanics, not just the fixed behaviour. If someone reintroduces the prune
/// loop, `Prune_is_not_automatic_and_gossip_cannot_resurrect` is the test that catches it.
/// </summary>
public class DirectoryLifecycleTests
{
    static AgentRecord Rec(string agent, string host, DateTime lastSeen, long version = 1, string status = "online") => new()
    {
        Agent = agent,
        Host = host,
        User = "test",
        Endpoint = $"http://{host}:8787",
        Endpoints = [$"http://{host}:8787"],
        Status = status,
        Version = version,
        LastSeen = lastSeen.ToString("yyyy-MM-ddTHH:mm:ssZ"),
    };

    static readonly DateTime Now = new(2026, 7, 17, 13, 0, 0, DateTimeKind.Utc);
    static DateTime HoursAgo(double h) => Now.AddHours(-h);

    // --- Fix 1 (FLOOR): a relay must never lose its own agents ------------------------------------

    [Fact]
    public void A_locally_hosted_record_is_never_stale_however_old_it_is()
    {
        // THE INCIDENT. wolf's own relay 404'd him at 24.2h because his record aged out of his own directory.
        // Resolve(name, Paths.Host) failing for a local agent is incoherent: a relay always knows what it hosts.
        var local = Rec("smiley", Paths.Host, HoursAgo(999));

        Assert.True(DirectoryStore.IsLocal(local));
        Assert.False(DirectoryStore.IsStale(local, Now));
        Assert.True(DirectoryStore.IsRoutable(local, Now));
    }

    [Fact]
    public void Explicit_prune_never_deletes_a_locally_hosted_record()
    {
        var local = Rec("smiley-prunetest", Paths.Host, HoursAgo(999));
        DirectoryStore.Save(local);
        try
        {
            DirectoryStore.PruneExplicit(Now.AddHours(-24));
            Assert.NotNull(DirectoryStore.Get(local.Agent, local.Host));
        }
        finally { DirectoryStore.Delete(local.Agent, local.Host); }
    }

    // --- Fix 2: prune + LWW gossip cannot coexist -------------------------------------------------

    [Fact]
    public void Prune_is_not_automatic_and_gossip_cannot_resurrect()
    {
        // The flap: prune deleted the file; a peer gossiped the record back (Merge sees current==null =>
        // IsNewer => Save); prune deleted it again. Delivery to a LIVE agent alternated 202/404 every ~60s
        // and neither end was told.
        //
        // A delete is indistinguishable from "never seen" under LWW, so any peer still holding the record
        // replays it straight back. The fix is that nothing deletes on a timer — asserted here by the absence
        // of any automatic reaper: an aged record simply survives.
        var remote = Rec("ghost", "some-peer", HoursAgo(99));
        DirectoryStore.Save(remote);
        try
        {
            Assert.True(DirectoryStore.IsStale(remote, Now));           // stale...
            Assert.NotNull(DirectoryStore.Get("ghost", "some-peer"));   // ...but still present, not erased

            // And a peer re-gossiping the identical record is a no-op rather than a resurrection event.
            Assert.False(DirectoryStore.Merge(remote));
        }
        finally { DirectoryStore.Delete("ghost", "some-peer"); }
    }

    [Fact]
    public void Deleting_a_record_destroys_the_LWW_high_water_so_a_re_register_can_lose_to_a_stale_ghost()
    {
        // Why deletion is not merely noisy but actively harmful. register computes
        // Version = (existing?.Version ?? 0) + 1, so re-registering into a DELETED slot restarts at v1 —
        // and a peer still holding v3 then wins the merge and silently undoes the recovery.
        //
        // This is the compounding failure behind #8: the flap's resurrection is the only thing that
        // accidentally preserved wolf's version when he re-registered.
        var ghostFromPeer = Rec("wolf", "some-peer-host", HoursAgo(30), version: 3);
        var freshAfterDeletion = Rec("wolf", "some-peer-host", Now, version: 1);   // version reset by the delete

        Assert.True(DirectoryStore.IsNewer(ghostFromPeer, freshAfterDeletion));

        // The stale 30h-old record beats the one minted seconds ago, purely on the version it kept.
        Assert.True(DirectoryStore.IsStale(ghostFromPeer, Now));
        Assert.False(DirectoryStore.IsStale(freshAfterDeletion, Now));
    }

    // --- Fix 3 + status-vs-freshness --------------------------------------------------------------

    [Fact]
    public void A_stale_record_that_still_says_online_is_NOT_routable()
    {
        // Wolf's required assertion. Status is self-asserted at register and never refreshed, so it cannot go
        // false: four agents were reporting "online" while unroutable, one of them for 37 hours. Freshness is
        // the signal; status is decoration.
        var staleButClaimsOnline = Rec("vincent", "desktop-bqgtlc4-7", HoursAgo(37), status: "online");

        Assert.Equal("online", staleButClaimsOnline.Status);
        Assert.True(DirectoryStore.IsStale(staleButClaimsOnline, Now));
        Assert.False(DirectoryStore.IsRoutable(staleButClaimsOnline, Now));
    }

    [Fact]
    public void A_fresh_record_is_routable_and_an_explicit_tombstone_is_not()
    {
        // The owner's explicit `register --offline` is the ONLY legitimate way to retire an agent, and it
        // bumps Version so the tombstone wins LWW and propagates instead of being resurrected.
        Assert.True(DirectoryStore.IsRoutable(Rec("harrell", "eric-aliya-laptop", HoursAgo(0.2)), Now));
        Assert.False(DirectoryStore.IsRoutable(Rec("retired", "eric-aliya-laptop", HoursAgo(0.2), status: "offline"), Now));
    }

    [Theory]
    [InlineData(0.1, false)]
    [InlineData(23.9, false)]
    [InlineData(24.2, true)]    // wolf's exact age at the incident
    [InlineData(37.3, true)]    // vincent, still claiming "online"
    [InlineData(60.9, true)]    // eric-main
    public void Staleness_is_decided_by_last_seen_age(double ageHours, bool expectStale) =>
        Assert.Equal(expectStale, DirectoryStore.IsStale(Rec("peer", "other-host", HoursAgo(ageHours)), Now));

    [Fact]
    public void An_unparseable_last_seen_is_treated_as_stale_but_is_still_not_deleted()
    {
        // Fail closed for ROUTING (we cannot prove freshness) without failing closed for EXISTENCE — deleting
        // on a parse error would hand any corrupt write the power to evict an agent.
        var broken = new AgentRecord { Agent = "broken", Host = "other-host", LastSeen = "not-a-date", Status = "online" };
        Assert.True(DirectoryStore.IsStale(broken, Now));
        Assert.False(DirectoryStore.IsRoutable(broken, Now));
    }

    [Fact]
    public void StaleAfter_defaults_to_24h()
    {
        // The knob is AGENTMAIL_STALE_HOURS — when a record stops being TRUSTED, not when it is erased.
        // AGENTMAIL_PRUNE_HOURS is gone with the prune loop.
        Assert.Equal(24, DirectoryStore.StaleAfter.TotalHours);
    }
}
