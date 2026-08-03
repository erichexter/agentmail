using AgentMail;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// The refusal hint must never name a host that nothing arrives at — that is the exact failure the
/// bare-name change exists to remove, so reproducing it inside the fix is the worst possible regression.
///
/// Found in the wild by maverick@desktop-bqgtlc4-7 during the 0.4.3 rollout: `--to harrell` there resolved
/// to BOTH the live `eric-aliya-laptop` and a stale truncated `eric-aliya-lapt` (v2, last_seen 11 days
/// old, an artefact of the #30/#31 host-truncation bug). The hint picked the first match and confidently
/// suggested the dead node.
///
/// These pin the selection rule against <see cref="DirectoryStore.IsStale"/>: prefer FRESH, then most
/// recently seen; only fall back to stale records when nothing fresh exists, and say so when that happens.
/// </summary>
public class StaleHostHintTests
{
    static AgentRecord Rec(string host, DateTime lastSeenUtc) => new()
    {
        Agent = "harrell",
        Host = host,
        LastSeen = lastSeenUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"),
    };

    [Fact]
    public void A_record_seen_just_now_is_not_stale()
    {
        Assert.False(DirectoryStore.IsStale(Rec("eric-aliya-laptop", DateTime.UtcNow.AddMinutes(-5))));
    }

    [Fact]
    public void The_truncated_eleven_day_old_record_is_stale()
    {
        // the exact shape maverick hit — a host-truncation leftover that outlived its usefulness
        Assert.True(DirectoryStore.IsStale(Rec("eric-aliya-lapt", DateTime.UtcNow.AddDays(-11))));
    }

    [Fact]
    public void Freshness_is_the_discriminator_not_registry_order()
    {
        // FindByName order is filesystem order; 'eric-aliya-lapt' sorts BEFORE 'eric-aliya-laptop',
        // which is why picking [0] chose the dead host. Freshness must override that ordering.
        var stale = Rec("eric-aliya-lapt", DateTime.UtcNow.AddDays(-11));
        var live = Rec("eric-aliya-laptop", DateTime.UtcNow.AddMinutes(-2));

        var candidates = new List<AgentRecord> { stale, live };   // registry order: dead one first
        var fresh = candidates.Where(r => !DirectoryStore.IsStale(r)).ToList();

        Assert.Single(fresh);
        Assert.Equal("eric-aliya-laptop", fresh[0].Host);
        Assert.NotEqual(candidates[0].Host, fresh[0].Host);       // proves order alone would have been wrong
    }

    [Fact]
    public void Among_several_fresh_records_the_most_recently_seen_wins()
    {
        var older = Rec("host-a", DateTime.UtcNow.AddHours(-6));
        var newer = Rec("host-b", DateTime.UtcNow.AddMinutes(-1));

        var best = new List<AgentRecord> { older, newer }
            .Where(r => !DirectoryStore.IsStale(r))
            .OrderByDescending(r => DirectoryStore.TryParseLastSeen(r, out var t) ? t : DateTime.MinValue)
            .First();

        Assert.Equal("host-b", best.Host);
    }

    [Fact]
    public void When_every_candidate_is_stale_there_is_no_fresh_pick_to_offer()
    {
        // 'wolf' today: windev2407eval and wolf-prime, both stale. The caller must fall back AND warn
        // rather than present the least-old guess as a working address.
        var all = new List<AgentRecord>
        {
            Rec("windev2407eval", DateTime.UtcNow.AddDays(-17)),
            Rec("wolf-prime",     DateTime.UtcNow.AddDays(-5)),
        };

        Assert.Empty(all.Where(r => !DirectoryStore.IsStale(r)));

        var fallback = all.OrderByDescending(r => DirectoryStore.TryParseLastSeen(r, out var t) ? t : DateTime.MinValue).First();
        Assert.Equal("wolf-prime", fallback.Host);   // least-old, but still explicitly flagged stale to the user
    }

    [Fact]
    public void An_unparseable_last_seen_is_treated_as_stale_not_as_fresh()
    {
        var junk = new AgentRecord { Agent = "harrell", Host = "somewhere", LastSeen = "not-a-date" };
        Assert.True(DirectoryStore.IsStale(junk));
    }
}
