using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// FLAG-48: the real requirement is CLOCK-REGRESSION SAFETY, not counter persistence.
///
/// It is easy to "fix" this by persisting a counter and still emit a backwards id after an NTP step, because
/// the timestamp — not the counter — is the high-order part of a ULID. These tests drive the clock backwards
/// explicitly rather than trusting that a restart happens to move forward.
/// </summary>
public class UlidTests
{
    static Ulid Fresh() => new(Path.Combine(TestRoot.Path, "state", Guid.NewGuid().ToString("N"), "ulid"));

    [Fact]
    public void Ids_are_26_chars_and_ascend_with_the_clock()
    {
        var u = Fresh();
        string a = u.Next(1_700_000_000_000);
        string b = u.Next(1_700_000_000_001);

        Assert.Equal(26, a.Length);
        Assert.Equal(26, b.Length);
        Assert.True(string.CompareOrdinal(a, b) < 0);
    }

    [Fact]
    public void A_backwards_clock_step_still_yields_a_strictly_increasing_id()
    {
        // The NTP-correction case. Naively taking the wall clock would mint a SMALLER id here, which can
        // collide with one already issued and breaks msg_id time-ordering.
        var u = Fresh();
        string before = u.Next(1_700_000_000_000);
        string afterStepBack = u.Next(1_699_999_000_000);   // clock jumps 1s into the past

        Assert.True(string.CompareOrdinal(afterStepBack, before) > 0,
            "an id minted after a backwards clock step must still sort after the previous id");
    }

    [Fact]
    public void Ids_minted_within_the_same_millisecond_are_unique_and_ordered()
    {
        var u = Fresh();
        var ids = Enumerable.Range(0, 200).Select(_ => u.Next(1_700_000_000_000)).ToList();

        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.Equal(ids.OrderBy(x => x, StringComparer.Ordinal), ids);
    }

    [Fact]
    public void The_high_water_mark_survives_a_restart()
    {
        string path = Path.Combine(TestRoot.Path, "state", Guid.NewGuid().ToString("N"), "ulid");

        string before = new Ulid(path).Next(1_700_000_000_000);
        string afterRestartWithRegressedClock = new Ulid(path).Next(1_699_999_000_000);

        // A fresh process that reads a regressed clock must still not go backwards — this is the case a
        // memory-only counter would miss entirely.
        Assert.True(string.CompareOrdinal(afterRestartWithRegressedClock, before) > 0);
    }
}
