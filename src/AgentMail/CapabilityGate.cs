using AgentMail.Crypto;

namespace AgentMail;

/// <summary>
/// Bridges the pure <see cref="Negotiation"/> decisions to real directory records — turns an AgentRecord pair
/// into the SelfState/PeerView the decision needs. Kept out of Negotiation so that module stays I/O-free and
/// exhaustively unit-testable; this adapter is the thin, record-shaped layer the relay calls.
/// </summary>
static class CapabilityGate
{
    static bool Advertises(AgentRecord? r, string cap) =>
        r is not null && r.Capabilities.Any(c => string.Equals(c, cap, StringComparison.OrdinalIgnoreCase));

    static ulong LastSeenMs(AgentRecord? r) =>
        r is not null && DirectoryStore.TryParseLastSeen(r, out var t)
            ? (ulong)new DateTimeOffset(t, TimeSpan.Zero).ToUnixTimeMilliseconds()
            : 0;

    /// <summary>
    /// FLAG-32/38 decision for an inbound LEGACY PLAINTEXT envelope to a local recipient.
    ///
    /// The recipient's own record supplies both "do I advertise e2e" and the advertisement anchor (its
    /// last_seen — when it last registered advertising e2e). Convergence is left conservative: ConvergenceObserved
    /// is false, so enforcement is gated purely on the grace period elapsing since that advertisement. Post-#8
    /// rollout that is the right signal — an agent whose e2e advertisement is older than the grace window has had
    /// time to propagate across a non-flapping directory. A cleanly partitioned peer never converges, so once
    /// grace elapses its plaintext is quarantined (fail closed) without ever blocking.
    /// </summary>
    public static InboundDecision InboundPlaintext(AgentRecord recipient, string senderKey, ulong nowMs)
    {
        var (sName, sHost) = AgentRef.Split(senderKey);
        var senderRec = sHost is null ? DirectoryStore.FindByName(sName).FirstOrDefault()
                                      : DirectoryStore.Get(sName, sHost);

        ulong advertisedAt = LastSeenMs(recipient);
        var self = new Negotiation.SelfState(
            AdvertisesE2e: Advertises(recipient, Capabilities.E2e),
            LocalRequireE2eOptOut: false,
            E2eAdvertisedAtMs: advertisedAt,
            ConvergenceObserved: false,     // conservative; grace-gated (see summary)
            StartupAtMs: advertisedAt);

        var peer = new Negotiation.PeerView(
            AdvertisesE2e: Advertises(senderRec, Capabilities.E2e),
            LastSeenMs: LastSeenMs(senderRec));

        return Negotiation.Inbound(self, peer, nowMs);
    }
}
