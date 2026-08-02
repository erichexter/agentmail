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

    /// <summary>
    /// Judge a relay response. A 2xx is NOT sufficient: the FLAG-32/38 CapabilityGate accepts a plaintext
    /// envelope for an e2e recipient with <c>202 Accepted</c> and then QUARANTINES it — the message is written
    /// to the recipient's quarantine/ directory and never reaches their inbox. Treating that 202 as success
    /// reports delivery for a message the recipient will never see, which is the same silent-failure class as
    /// the phantom-inbox bug. The reason is only in the body, so the body has to be read.
    /// Kept as a body check rather than changing the relay's status code, so a new sender stays compatible
    /// with older relays already deployed across the fleet.
    /// </summary>
    internal static (bool ok, string detail) Judge(int status, string? reason, string body)
    {
        string detail = $"{status} {reason} {body}".Trim();
        bool http2xx = status is >= 200 and < 300;
        if (http2xx && body.Contains("\"quarantined\"", StringComparison.OrdinalIgnoreCase))
            return (false, $"QUARANTINED, not delivered — the relay accepted then quarantined this message " +
                           $"and the recipient will not see it. {detail}");
        return (http2xx, detail);
    }

    public static async Task<(bool ok, string detail)> SendInbox(string endpoint, string token, Envelope env)
    {
        try
        {
            using var req = Auth(HttpMethod.Post, $"{endpoint}/inbox", token, JsonContent.Create(env, options: Paths.Json));
            using var res = await Http.SendAsync(req);
            string body = await res.Content.ReadAsStringAsync();
            return Judge((int)res.StatusCode, res.ReasonPhrase, body);
        }
        catch (Exception e) { return (false, e.Message); }
    }

    /// <summary>POST a SEALED envelope to a peer's relay. Same /inbox endpoint — the relay detects `enc` and
    /// routes it through the consume/verify path instead of a plaintext file-drop (activation slice).</summary>
    public static async Task<(bool ok, string detail)> SendSealed(string endpoint, string token, Crypto.SealedEnvelope env)
    {
        try
        {
            using var req = Auth(HttpMethod.Post, $"{endpoint}/inbox", token, JsonContent.Create(env, options: Paths.Json));
            using var res = await Http.SendAsync(req);
            string body = await res.Content.ReadAsStringAsync();
            return Judge((int)res.StatusCode, res.ReasonPhrase, body);
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
