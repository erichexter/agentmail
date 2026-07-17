namespace AgentMail;

/// <summary>
/// The capabilities this binary advertises. Printed by `agentmail --caps` and, for the network-facing ones,
/// carried in AgentRecord.Capabilities so peers can negotiate (capability negotiation lands in the last
/// slice, FLAG-32/38).
/// </summary>
static class Capabilities
{
    /// <summary>This binary reads and writes E2E envelopes as *.msg.json (FLAG-9.2/9.4). A watcher probes for
    /// this before it will glob *.msg.json — its presence is what makes feeding json to this binary safe.</summary>
    public const string MsgJson = "msg-json";

    /// <summary>This node speaks E2E: it advertises `e2e` in its record and reads *.msg.json. FLAG-9.2 —
    /// a sender MUST NOT emit *.msg.json to a peer that has not advertised this.</summary>
    public const string E2e = "e2e";

    /// <summary>Everything `--caps` prints. Order is stable so a watcher can grep a fixed token.</summary>
    public static readonly string[] All = [MsgJson, E2e];
}
