namespace AgentMail;

/// <summary>Peer discovery for gossip: seeds ∪ every other host seen in the directory.</summary>
static class Gossip
{
    public static List<string> Peers(TailscaleInfo ts, Config config)
    {
        string mine = ts.EndpointFor(config.Port);
        var set = new HashSet<string>(config.Seeds, StringComparer.OrdinalIgnoreCase);
        foreach (var r in DirectoryStore.All())
            if (!string.IsNullOrWhiteSpace(r.Endpoint) &&
                !string.Equals(r.Host, Paths.Host, StringComparison.OrdinalIgnoreCase))
                set.Add(r.Endpoint);
        set.Remove(mine);
        return set.ToList();
    }
}
