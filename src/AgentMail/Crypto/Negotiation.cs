namespace AgentMail.Crypto;

/// <summary>What the recipient does with an INBOUND plaintext message, given the sender and convergence state.</summary>
enum InboundDecision
{
    /// <summary>Deliver normally — legacy path (I don't require e2e, or the sender is a legacy peer).</summary>
    Deliver,
    /// <summary>Deliver, but alert: an e2e peer sent plaintext during my convergence window and legitimately
    /// may not know yet that I do e2e. Accepted-with-alert, NOT blackholed (FLAG-38).</summary>
    DeliverWithAlert,
    /// <summary>Quarantine + alert: an e2e peer sent plaintext when it should have sealed (converged, or its
    /// record postdates my e2e advertisement). Full FLAG-32 enforcement.</summary>
    Quarantine,
}

/// <summary>What the sender does when routing a message to a peer (FLAG-32 sender bullet + FLAG-11).</summary>
enum OutboundDecision
{
    /// <summary>Seal E2E — the peer advertises e2e and its Keys bundle is available.</summary>
    Seal,
    /// <summary>Send legacy plaintext, with an alert — the peer is legacy (no e2e) and does not require e2e.</summary>
    PlaintextWithAlert,
    /// <summary>Hold + alert — the peer advertises e2e but its Keys are missing/unreachable. Never downgrade an
    /// e2e peer to plaintext (FLAG-32). NOT a block: the caller alerts and moves on; the message waits.</summary>
    HoldNoKeys,
    /// <summary>Refuse + alert — require_e2e is set for this peer but no Keys are available. Never plaintext.</summary>
    RefuseRequireE2e,
}

/// <summary>
/// Capability negotiation (FLAG-32/38). Pure decisions — no I/O — so the convergence-gating, which is the
/// subtle part, is fully testable. The relay/consume/send paths call these and act on the result.
///
/// The property FLAG-38 exists for: a freshly-started e2e agent advertises e2e locally at once, but that hasn't
/// propagated, so peers still send plaintext. A naive "e2e agent quarantines all plaintext" would blackhole its
/// own inbound for the whole propagation window. So ENFORCEMENT is gated on convergence evidence, not on the
/// flag. This shipped only after the #8 directory fix reached every relay — convergence-gating on a directory
/// that still flaps would sit on the exact race it defends against. A cleanly PARTITIONED peer (the
/// isolated-tailnet peer) is not that race: it never reflects my advertisement, so post-grace I fail closed
/// (quarantine its plaintext) without ever blocking on it.
/// </summary>
static class Negotiation
{
    /// <summary>Default startup grace before an e2e agent enforces against not-yet-converged peers (FLAG-38).</summary>
    public static TimeSpan ConvergenceGrace { get; } =
        TimeSpan.FromMinutes(EnvInt("AGENTMAIL_E2E_CONVERGENCE_GRACE_MIN", 10));

    static int EnvInt(string name, int fallback) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out int v) && v > 0 ? v : fallback;

    /// <summary>My own e2e-participation + convergence state. Immutable snapshot passed into a decision.</summary>
    public readonly record struct SelfState(
        bool AdvertisesE2e,        // do I publish the `e2e` capability? (sets local_require_e2e on, FLAG-32)
        bool LocalRequireE2eOptOut,// explicit opt-OUT (FLAG-32 is opt-out, not opt-in)
        ulong E2eAdvertisedAtMs,   // when I started advertising e2e (my record's timestamp)
        bool ConvergenceObserved,  // have I seen ANY peer reflect my e2e advertisement?
        ulong StartupAtMs)         // when this agent started (grace anchor)
    {
        public bool Converged(ulong nowMs) =>
            ConvergenceObserved || nowMs >= StartupAtMs + (ulong)ConvergenceGrace.TotalMilliseconds;

        /// <summary>local_require_e2e is ON for any e2e agent unless it explicitly opted out (FLAG-32).</summary>
        public bool LocalRequireE2e => AdvertisesE2e && !LocalRequireE2eOptOut;
    }

    /// <summary>A peer as seen in the directory: does it advertise e2e, and when was its record last seen.</summary>
    public readonly record struct PeerView(bool AdvertisesE2e, ulong LastSeenMs);

    /// <summary>
    /// Decide what to do with an inbound PLAINTEXT message from <paramref name="peer"/> (FLAG-32/38).
    /// (Sealed E2E messages never reach here — they go through the consume/verify path.)
    /// </summary>
    public static InboundDecision Inbound(SelfState self, PeerView peer, ulong nowMs)
    {
        // I don't require e2e (legacy agent, or explicit opt-out) -> deliver everything (FLAG-32: legacy defaults off).
        if (!self.LocalRequireE2e) return InboundDecision.Deliver;

        // A legacy peer (doesn't advertise e2e) sending plaintext is normal -> deliver. FLAG-32 gates plaintext
        // from an e2e-ADVERTISING peer, not from a peer that never claimed to do e2e.
        if (!peer.AdvertisesE2e) return InboundDecision.Deliver;

        // From here: I require e2e AND the peer advertises e2e, yet it sent plaintext.
        if (self.Converged(nowMs))
            return InboundDecision.Quarantine;   // full enforcement — it should have sealed

        // Convergence/grace window (FLAG-38): don't blackhole a peer that legitimately hasn't learned I do e2e.
        //   peer record PREDATES my advertisement -> it hasn't seen my e2e yet -> accept-with-alert
        //   peer record POSTDATES my advertisement -> it should know -> quarantine
        return peer.LastSeenMs < self.E2eAdvertisedAtMs
            ? InboundDecision.DeliverWithAlert
            : InboundDecision.Quarantine;
    }

    /// <summary>
    /// Decide how to route an OUTBOUND message to a peer (FLAG-32 sender bullet + FLAG-11).
    ///
    /// <paramref name="haveKeys"/>: a usable Keys bundle for the peer is available (fetched or gossiped).
    /// <paramref name="requireE2e"/>: this send requires e2e — either the caller set it, or the downgrade-replay
    /// default (any peer ever observed advertising e2e is treated require_e2e=true, FLAG-32).
    /// </summary>
    public static OutboundDecision Outbound(PeerView peer, bool haveKeys, bool requireE2e)
    {
        if (peer.AdvertisesE2e || requireE2e)
        {
            if (haveKeys) return OutboundDecision.Seal;
            // e2e peer but no Keys: NEVER downgrade to plaintext. Require -> refuse; else hold. Neither blocks —
            // the caller alerts and the message waits for Keys (or for the partition to heal). This is the
            // fail-closed-no-block posture for a partitioned peer.
            return requireE2e ? OutboundDecision.RefuseRequireE2e : OutboundDecision.HoldNoKeys;
        }
        // Legacy peer, no e2e requirement -> plaintext, with an alert so a silent downgrade is visible.
        return OutboundDecision.PlaintextWithAlert;
    }
}
