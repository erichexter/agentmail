using AgentMail;
using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// The sealed path must carry the ENVELOPE, not just the body.
/// </summary>
/// <remarks>
/// Regression cover for the bug fixed 2026-09-03. <c>Program.cs</c> sealed
/// <c>Encoding.UTF8.GetBytes(body)</c> — the bare message text — while every unsealed path
/// (<c>Relay.cs:112</c>, <c>Program.cs:309</c>) wrote <c>env.Serialize()</c>, which is what emits the
/// <c>---</c> frontmatter. So an encrypted cross-machine message was delivered as an anonymous
/// document: no id, no from, no to, no subject, no sent.
///
/// <para>The cost was not cosmetic. Four such messages reached garrison and sixteen reached harrell,
/// every one legitimate, and they were treated as untrusted precisely because the recipient could not
/// attribute them from the file. Two agents were nearly asked to fix a sender-side bug they did not
/// have.</para>
///
/// <para><b>Why this test can fail.</b> The suite had 166 tests and none of them opened a sealed
/// payload and looked for an envelope, so the bug survived every one of them. The assertions below
/// are written against the RECOVERED FIELDS rather than against a byte-equality round-trip: a
/// round-trip test passes just as happily when the plaintext is a bare body, which is exactly how
/// this went unnoticed. Sealing the body alone fails
/// <c>Sealed_payload_carries_the_envelope_not_just_the_body</c> on the first assert.</para>
/// </remarks>
public class SealedEnvelopeRoundTripTests
{
    readonly string _tag = Guid.NewGuid().ToString("N")[..8];

    (Identity sender, Identity recipient) Pair() =>
        (Id($"steele-{_tag}", "eric-aliya-laptop"), Id($"garrison-{_tag}", "cto"));

    static Identity Id(string name, string host) => Identity.LoadOrCreate(new Address(name, host));

    static Envelope SampleEnvelope() => new()
    {
        Id      = "abc123def456",
        From    = "steele",
        To      = "garrison@cto",
        Subject = "dev3 deploy ask",
        ReplyTo = "steele",
        Sent    = "2026-09-03T10:00:00Z",
        Body    = "The body of the message.\n",
    };

    [Fact]
    public void Sealed_payload_carries_the_envelope_not_just_the_body()
    {
        var (sender, recipient) = Pair();
        var env = SampleEnvelope();

        // env.SealPayload() is EXACTLY what the send path passes to Seal.Create. Calling
        // Seal.Create with hand-built bytes would pass against the buggy caller too — the test has
        // to exercise the caller's choice, not re-make it.
        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AB", env.SealPayload());

        var delivered = System.Text.Encoding.UTF8.GetString(Seal.Open(recipient, e, sender.PublicKey));

        // What the recipient actually writes to the inbox must be parseable as an envelope.
        Assert.StartsWith("---", delivered);

        var parsed = Envelope.Parse(delivered);
        Assert.Equal(env.From, parsed.From);
        Assert.Equal(env.To, parsed.To);
        Assert.Equal(env.Subject, parsed.Subject);
        Assert.Equal(env.ReplyTo, parsed.ReplyTo);
        Assert.Equal(env.Sent, parsed.Sent);
        Assert.Equal(env.Id, parsed.Id);
        Assert.Contains("The body of the message.", parsed.Body);
    }

    [Fact]
    public void A_body_only_seal_is_exactly_what_the_bug_looked_like()
    {
        // Pins the failure shape itself, so a future refactor that quietly reverts to sealing the
        // body is recognisable as THIS bug rather than as a mystery. A recipient handed this cannot
        // say who sent it — which is the whole defect.
        var (sender, recipient) = Pair();
        var env = SampleEnvelope();

        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AC",
                            System.Text.Encoding.UTF8.GetBytes(env.Body));

        var delivered = System.Text.Encoding.UTF8.GetString(Seal.Open(recipient, e, sender.PublicKey));

        Assert.DoesNotContain("---", delivered);
        Assert.DoesNotContain("from:", delivered);
    }
}
