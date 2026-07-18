using AgentMail.Crypto;
using Xunit;
using static AgentMail.Crypto.Negotiation;

namespace AgentMail.Tests;

/// <summary>
/// Capability negotiation (FLAG-32/38). The convergence-gating is the subtle part — a naive default-on policy
/// blackholes a freshly-started agent's own inbound during gossip propagation. These pin the four inbound
/// cases and the outbound fail-closed-no-block posture, including the clean-partition scenario.
/// </summary>
public class NegotiationTests
{
    const ulong T0 = 1_752_700_000_000;   // my e2e advertisement time
    const ulong Grace = 10UL * 60 * 1000; // default 10 min

    static SelfState E2eAgent(bool converged = false, ulong startupAt = T0, bool optOut = false) =>
        new(AdvertisesE2e: true, LocalRequireE2eOptOut: optOut, E2eAdvertisedAtMs: T0,
            ConvergenceObserved: converged, StartupAtMs: startupAt);

    static SelfState LegacyAgent() =>
        new(AdvertisesE2e: false, LocalRequireE2eOptOut: false, E2eAdvertisedAtMs: 0,
            ConvergenceObserved: false, StartupAtMs: T0);

    // --- Inbound plaintext (FLAG-32/38) ----------------------------------------------------------

    [Fact]
    public void A_legacy_agent_delivers_all_plaintext()
    {
        // FLAG-32: a non-e2e agent defaults local_require_e2e off.
        var d = Inbound(LegacyAgent(), new PeerView(AdvertisesE2e: true, LastSeenMs: T0 + 5000), T0 + 6000);
        Assert.Equal(InboundDecision.Deliver, d);
    }

    [Fact]
    public void An_e2e_agent_delivers_plaintext_from_a_LEGACY_peer()
    {
        // A peer that never claimed e2e sending plaintext is normal — FLAG-32 gates plaintext from an
        // e2e-ADVERTISING peer, not from a legacy one.
        var d = Inbound(E2eAgent(converged: true), new PeerView(AdvertisesE2e: false, LastSeenMs: T0), T0 + 999_999);
        Assert.Equal(InboundDecision.Deliver, d);
    }

    [Fact]
    public void A_CONVERGED_e2e_agent_quarantines_plaintext_from_an_e2e_peer()
    {
        // Full FLAG-32 enforcement: an e2e peer that sends plaintext when I'm converged should have sealed.
        var d = Inbound(E2eAgent(converged: true), new PeerView(AdvertisesE2e: true, LastSeenMs: T0 + 5000), T0 + 6000);
        Assert.Equal(InboundDecision.Quarantine, d);
    }

    [Fact]
    public void During_grace_plaintext_from_a_peer_whose_record_PREDATES_my_advertisement_is_accepted_with_alert()
    {
        // FLAG-38 the core anti-blackhole case: the peer legitimately hasn't learned I do e2e yet, so I must
        // NOT quarantine — that would blackhole my own inbound during the propagation window.
        var d = Inbound(E2eAgent(converged: false, startupAt: T0),
                        new PeerView(AdvertisesE2e: true, LastSeenMs: T0 - 1000),   // predates my advert
                        T0 + 1000);                                                  // still within grace
        Assert.Equal(InboundDecision.DeliverWithAlert, d);
    }

    [Fact]
    public void During_grace_plaintext_from_a_peer_whose_record_POSTDATES_my_advertisement_is_quarantined()
    {
        // FLAG-38: a peer whose record is newer than my advertisement SHOULD know I do e2e — plaintext from it
        // is quarantined even during grace.
        var d = Inbound(E2eAgent(converged: false, startupAt: T0),
                        new PeerView(AdvertisesE2e: true, LastSeenMs: T0 + 2000),   // postdates my advert
                        T0 + 3000);                                                  // within grace
        Assert.Equal(InboundDecision.Quarantine, d);
    }

    [Fact]
    public void After_the_grace_period_elapses_enforcement_is_full_even_without_observed_convergence()
    {
        // FLAG-38 (b): grace elapsing is convergence evidence on its own. This is also the partitioned-peer
        // case — a partitioned peer never reflects my advertisement, so ConvergenceObserved stays false, but
        // grace still elapses and I fail closed.
        var partitionedPeer = new PeerView(AdvertisesE2e: true, LastSeenMs: T0 - 5000);   // predates, but...
        var d = Inbound(E2eAgent(converged: false, startupAt: T0), partitionedPeer, T0 + Grace + 1);
        Assert.Equal(InboundDecision.Quarantine, d);   // ...post-grace, fail closed
    }

    [Fact]
    public void Observed_convergence_enforces_immediately_even_inside_the_grace_window()
    {
        // If a peer has already reflected my e2e advertisement, I'm converged regardless of the clock.
        var d = Inbound(E2eAgent(converged: true, startupAt: T0),
                        new PeerView(AdvertisesE2e: true, LastSeenMs: T0 - 1000), T0 + 1);
        Assert.Equal(InboundDecision.Quarantine, d);
    }

    [Fact]
    public void An_explicit_opt_out_makes_an_e2e_agent_deliver_plaintext_like_legacy()
    {
        // FLAG-32 is opt-OUT: local_require_e2e=false is honored.
        var d = Inbound(E2eAgent(converged: true, optOut: true),
                        new PeerView(AdvertisesE2e: true, LastSeenMs: T0 + 5000), T0 + 6000);
        Assert.Equal(InboundDecision.Deliver, d);
    }

    // --- Outbound (FLAG-32 sender + FLAG-11) -----------------------------------------------------

    [Fact]
    public void Outbound_to_an_e2e_peer_with_keys_seals()
    {
        Assert.Equal(OutboundDecision.Seal,
            Outbound(new PeerView(AdvertisesE2e: true, LastSeenMs: T0), haveKeys: true, requireE2e: false));
    }

    [Fact]
    public void Outbound_to_an_e2e_peer_with_NO_keys_holds_never_downgrades()
    {
        // FLAG-32: never plaintext to an e2e peer. Hold + alert — this is the partitioned-peer case: no seal
        // (no Keys), no block (the caller alerts and the message waits).
        Assert.Equal(OutboundDecision.HoldNoKeys,
            Outbound(new PeerView(AdvertisesE2e: true, LastSeenMs: T0), haveKeys: false, requireE2e: false));
    }

    [Fact]
    public void Outbound_with_require_e2e_and_no_keys_refuses_never_downgrades()
    {
        Assert.Equal(OutboundDecision.RefuseRequireE2e,
            Outbound(new PeerView(AdvertisesE2e: false, LastSeenMs: T0), haveKeys: false, requireE2e: true));
    }

    [Fact]
    public void Outbound_to_a_legacy_peer_with_no_requirement_is_plaintext_with_alert()
    {
        Assert.Equal(OutboundDecision.PlaintextWithAlert,
            Outbound(new PeerView(AdvertisesE2e: false, LastSeenMs: T0), haveKeys: false, requireE2e: false));
    }

    [Fact]
    public void Downgrade_replay_defense_a_peer_ever_seen_advertising_e2e_is_required_even_if_its_current_view_is_legacy()
    {
        // FLAG-32: require_e2e=true defaults on for any peer ever observed advertising e2e. Even if the CURRENT
        // record looks legacy (a downgrade-replay), requireE2e=true forces refuse-not-plaintext.
        Assert.Equal(OutboundDecision.RefuseRequireE2e,
            Outbound(new PeerView(AdvertisesE2e: false, LastSeenMs: T0), haveKeys: false, requireE2e: true));
    }
}
