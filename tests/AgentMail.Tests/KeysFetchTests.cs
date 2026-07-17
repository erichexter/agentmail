using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// Signed GET /keys (brief PR1.4). The property that matters: a fetch is authenticated to the FETCHER'S
/// identity key, so possession of the shared bearer token alone does not authorize a key harvest.
/// </summary>
public class KeysFetchTests
{
    readonly string _tag = Guid.NewGuid().ToString("N")[..8];
    Identity Id(string name) => Identity.LoadOrCreate(new Address($"{name}-{_tag}", "peer-host"));

    const ulong Now = 1_752_700_000_000;

    [Fact]
    public void A_correctly_signed_recent_fetch_verifies()
    {
        var auth = KeysFetchAuth.Create(Id("smiley"), new Address("wolf", "gateway"), requestedAt: Now);
        Assert.Null(auth.Verify(Now));
    }

    [Fact]
    public void A_tampered_target_fails_because_the_target_is_signed()
    {
        // The requester signs (requester, target, time). Redirecting the fetch to a different target after
        // signing must break the signature — otherwise a captured auth could be replayed against any target.
        var auth = KeysFetchAuth.Create(Id("smiley"), new Address("wolf", "gateway"), requestedAt: Now);
        auth.Target = new Address("victim", "gateway");
        Assert.NotNull(auth.Verify(Now));
    }

    [Fact]
    public void A_forged_signature_is_rejected()
    {
        var auth = KeysFetchAuth.Create(Id("smiley"), new Address("wolf", "gateway"), requestedAt: Now);
        auth.Signature[0] ^= 0xFF;
        Assert.Equal("fetch signature verification failed", auth.Verify(Now));
    }

    [Fact]
    public void A_signature_over_the_right_fields_but_a_DIFFERENT_ident_pub_is_rejected()
    {
        // Present a valid signature but swap in someone else's public key — the signature no longer matches the
        // presented key. This is what stops a bare-token holder from minting a fetch under a claimed identity.
        var real = KeysFetchAuth.Create(Id("smiley"), new Address("wolf", "gateway"), requestedAt: Now);
        real.RequesterIdentPub = Id("someone-else").PublicKey;
        Assert.Equal("fetch signature verification failed", real.Verify(Now));
    }

    [Theory]
    [InlineData(0, true)]                       // same instant
    [InlineData(4 * 60 * 1000, true)]           // 4 min — within the 5 min window
    [InlineData(6 * 60 * 1000, false)]          // 6 min — stale
    [InlineData(-6 * 60 * 1000, false)]         // 6 min in the future — also rejected
    public void The_fetch_timestamp_must_be_within_the_bounded_window(long skewMs, bool shouldPass)
    {
        var auth = KeysFetchAuth.Create(Id("smiley"), new Address("wolf", "gateway"), requestedAt: Now);
        string? result = auth.Verify((ulong)((long)Now + skewMs));
        if (shouldPass) Assert.Null(result); else Assert.NotNull(result);
    }

    [Fact]
    public void The_header_round_trips()
    {
        var auth = KeysFetchAuth.Create(Id("smiley"), new Address("wolf", "gateway"), requestedAt: Now);
        var restored = KeysFetchAuth.FromHeader(auth.ToHeader());
        Assert.NotNull(restored);
        Assert.Null(restored!.Verify(Now));
    }

    [Fact]
    public void A_missing_or_malformed_header_is_null_not_a_crash()
    {
        Assert.Null(KeysFetchAuth.FromHeader(null));
        Assert.Null(KeysFetchAuth.FromHeader(""));
        Assert.Null(KeysFetchAuth.FromHeader("not-base64-!!!"));
        Assert.Null(KeysFetchAuth.FromHeader(Convert.ToBase64String("{}"u8.ToArray()) + "garbage"));
    }

    [Fact]
    public void A_published_bundle_round_trips_as_the_self_signed_AgentCertLite()
    {
        var id = Id("wolf");
        var published = AgentCertLite.Create(id, recordEpoch: 3);
        KeysBundle.Publish(published);

        var served = KeysBundle.Get(id.Address);
        Assert.NotNull(served);
        Assert.True(served!.VerifySelfSignature());
        Assert.Equal(published.KeyId, served.KeyId);
        Assert.Equal(3ul, served.RecordEpoch);
    }

    [Fact]
    public void GetKeys_returns_null_for_an_agent_this_relay_does_not_host()
    {
        Assert.Null(KeysBundle.Get(new Address($"nobody-{_tag}", "peer-host")));
    }
}
