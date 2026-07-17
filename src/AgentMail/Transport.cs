using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace AgentMail;

/// <summary>HTTP client for talking to a peer's relay. JSON bodies, bearer-token auth.</summary>
static class Transport
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static HttpRequestMessage Auth(HttpMethod m, string url, string token, HttpContent? body)
    {
        var req = new HttpRequestMessage(m, url) { Content = body };
        if (token.Length > 0) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return req;
    }

    public static async Task<(bool ok, string detail)> SendInbox(string endpoint, string token, Envelope env)
    {
        try
        {
            using var req = Auth(HttpMethod.Post, $"{endpoint}/inbox", token, JsonContent.Create(env, options: Paths.Json));
            using var res = await Http.SendAsync(req);
            string detail = await res.Content.ReadAsStringAsync();
            return (res.IsSuccessStatusCode, $"{(int)res.StatusCode} {res.ReasonPhrase} {detail}".Trim());
        }
        catch (Exception e) { return (false, e.Message); }
    }

    public static async Task<(bool ok, string detail)> Register(string endpoint, string token, AgentRecord rec)
    {
        try
        {
            using var req = Auth(HttpMethod.Post, $"{endpoint}/register", token, JsonContent.Create(rec, options: Paths.Json));
            using var res = await Http.SendAsync(req);
            return (res.IsSuccessStatusCode, $"{(int)res.StatusCode} {res.ReasonPhrase}".Trim());
        }
        catch (Exception e) { return (false, e.Message); }
    }

    /// <summary>
    /// Fetch a peer's identity-only Keys bundle (its AgentCertLite) via a SIGNED GET /keys (brief PR1.4).
    /// The request is authenticated to the fetcher's Ed25519 identity, not the shared bearer token.
    /// Returns null on 404 (relay doesn't host the target) or any failure — the caller falls back to the
    /// gossiped record (FLAG-9.3/FLAG-13), it does not treat this as fatal.
    /// </summary>
    public static async Task<Crypto.AgentCertLite?> GetKeys(string endpoint, Crypto.Identity requester, Crypto.Address target)
    {
        try
        {
            var auth = Crypto.KeysFetchAuth.Create(requester, target);
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{endpoint}/keys?to={Uri.EscapeDataString(target.Key)}");
            req.Headers.Add(Crypto.KeysFetchAuth.HeaderName, auth.ToHeader());
            using var res = await Http.SendAsync(req);
            if (!res.IsSuccessStatusCode) return null;
            return Crypto.KeysBundle.Deserialize(await res.Content.ReadAsStringAsync());
        }
        catch { return null; }
    }

    /// <summary>Quick liveness probe of a relay endpoint (GET /health). Used to pick a reachable address.</summary>
    public static async Task<bool> Probe(string endpoint, int timeoutMs = 2500)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            using var res = await Http.GetAsync($"{endpoint}/health", cts.Token);
            return res.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public static async Task<List<AgentRecord>?> GetAgents(string endpoint)
    {
        try { return await Http.GetFromJsonAsync<List<AgentRecord>>($"{endpoint}/agents", Paths.Json); }
        catch { return null; }
    }

    /// <summary>Anti-entropy exchange: send our records, get back the peer's newer/unknown ones to merge.</summary>
    public static async Task<List<AgentRecord>?> Gossip(string endpoint, string token, List<AgentRecord> records)
    {
        try
        {
            using var req = Auth(HttpMethod.Post, $"{endpoint}/gossip", token, JsonContent.Create(records, options: Paths.Json));
            using var res = await Http.SendAsync(req);
            return res.IsSuccessStatusCode ? await res.Content.ReadFromJsonAsync<List<AgentRecord>>(Paths.Json) : null;
        }
        catch { return null; }
    }
}
