using AgentMail;
using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// The record-shaped adapter over Negotiation — exercises the FLAG-32/38 decision through real AgentRecords in
/// the directory, the way the relay's /inbox handler calls it. Complements NegotiationTests (which pins the
/// pure logic) by proving the record→decision mapping is right.
/// </summary>
public class CapabilityGateTests
{
    readonly string _tag = Guid.NewGuid().ToString("N")[..8];

    AgentRecord Save(string name, bool e2e, DateTime lastSeen)
    {
        var r = new AgentRecord
        {
            Agent = $"{name}-{_tag}",
            Host = "peer-host",
            Endpoint = "http://peer-host:8787",
            Status = "online",
            Version = 1,
            LastSeen = lastSeen.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Capabilities = e2e ? new List<string> { Capabilities.MsgJson, Capabilities.E2e } : new List<string>(),
        };
        DirectoryStore.Save(r);
        return r;
    }

    static ulong Ms(DateTime utc) => (ulong)new DateTimeOffset(utc, TimeSpan.Zero).ToUnixTimeMilliseconds();
    static readonly DateTime Base = new(2026, 7, 17, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void A_legacy_recipient_delivers_plaintext_from_anyone()
    {
        var recipient = Save("legacyrcpt", e2e: false, lastSeen: Base);
        var sender = Save("e2esender", e2e: true, lastSeen: Base);
        var d = CapabilityGate.InboundPlaintext(recipient, sender.Key, Ms(Base.AddMinutes(20)));
        Assert.Equal(InboundDecision.Deliver, d);
    }

    [Fact]
    public void An_e2e_recipient_delivers_plaintext_from_a_legacy_sender()
    {
        var recipient = Save("e2ercpt", e2e: true, lastSeen: Base);
        var sender = Save("legacysender", e2e: false, lastSeen: Base);
        var d = CapabilityGate.InboundPlaintext(recipient, sender.Key, Ms(Base.AddMinutes(20)));
        Assert.Equal(InboundDecision.Deliver, d);
    }

    [Fact]
    public void A_converged_e2e_recipient_quarantines_plaintext_from_an_e2e_sender()
    {
        // Recipient advertised e2e 20 min ago (> 10 min grace) -> converged -> full enforcement.
        var recipient = Save("e2ercpt", e2e: true, lastSeen: Base);
        var sender = Save("e2esender", e2e: true, lastSeen: Base.AddMinutes(5));
        var d = CapabilityGate.InboundPlaintext(recipient, sender.Key, Ms(Base.AddMinutes(20)));
        Assert.Equal(InboundDecision.Quarantine, d);
    }

    [Fact]
    public void During_grace_an_e2e_sender_whose_record_predates_the_recipients_advertisement_is_accepted_with_alert()
    {
        // Recipient advertised at Base; sender's record is older; we're 2 min in (< 10 min grace). The sender
        // legitimately hasn't learned the recipient does e2e -> accept-with-alert, not blackhole (FLAG-38).
        var recipient = Save("e2ercpt", e2e: true, lastSeen: Base);
        var sender = Save("e2esender", e2e: true, lastSeen: Base.AddMinutes(-5));
        var d = CapabilityGate.InboundPlaintext(recipient, sender.Key, Ms(Base.AddMinutes(2)));
        Assert.Equal(InboundDecision.DeliverWithAlert, d);
    }

    [Fact]
    public void During_grace_an_e2e_sender_whose_record_postdates_the_advertisement_is_quarantined()
    {
        var recipient = Save("e2ercpt", e2e: true, lastSeen: Base);
        var sender = Save("e2esender", e2e: true, lastSeen: Base.AddMinutes(3));   // knows, or should
        var d = CapabilityGate.InboundPlaintext(recipient, sender.Key, Ms(Base.AddMinutes(4)));
        Assert.Equal(InboundDecision.Quarantine, d);
    }

    [Fact]
    public void A_partitioned_e2e_peer_is_quarantined_after_grace_never_blocks()
    {
        // the isolated-tailnet case: a partitioned peer never converges, but grace elapses, so its plaintext is
        // quarantined (fail closed). The decision returns immediately — no blocking on the partition.
        var recipient = Save("e2ercpt", e2e: true, lastSeen: Base);
        var partitioned = Save("partitioned-peer", e2e: true, lastSeen: Base.AddMinutes(-30));  // old, isolated
        var d = CapabilityGate.InboundPlaintext(recipient, partitioned.Key, Ms(Base.AddMinutes(15)));
        Assert.Equal(InboundDecision.Quarantine, d);
    }

    [Fact]
    public void An_unknown_sender_is_treated_as_legacy_and_delivered()
    {
        // No record for the sender -> AdvertisesE2e false -> a plaintext from a name we've never seen is not
        // gated (it never claimed e2e). Delivered (an unpinned/unknown SEALED sender is separately handled by
        // the consume path; this is the plaintext relay path).
        var recipient = Save("e2ercpt", e2e: true, lastSeen: Base);
        var d = CapabilityGate.InboundPlaintext(recipient, $"ghost-{_tag}@nowhere", Ms(Base.AddMinutes(20)));
        Assert.Equal(InboundDecision.Deliver, d);
    }
}
