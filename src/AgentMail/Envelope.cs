using System.Text;
using System.Text.Json.Serialization;

namespace AgentMail;

/// <summary>
/// A message: a small key/value frontmatter block fenced by "---" lines, then a markdown body.
/// Deliberately hand-parsed (no YAML dependency) and human-writable.
/// </summary>
sealed class Envelope
{
    public string Id { get; set; } = "";
    public string From { get; set; } = "";
    public string To { get; set; } = "";
    public string Subject { get; set; } = "";
    public string? ReplyTo { get; set; }
    public string Sent { get; set; } = "";
    public string Body { get; set; } = "";

    [JsonIgnore] public string FileName => $"{Id}.msg.md";

    public string Serialize()
    {
        var sb = new StringBuilder();
        sb.Append("---\n");
        sb.Append($"id: {Id}\n");
        sb.Append($"from: {From}\n");
        sb.Append($"to: {To}\n");
        sb.Append($"subject: {Subject}\n");
        if (!string.IsNullOrWhiteSpace(ReplyTo)) sb.Append($"reply_to: {ReplyTo}\n");
        sb.Append($"sent: {Sent}\n");
        sb.Append("---\n");
        sb.Append(Body);
        if (!Body.EndsWith('\n')) sb.Append('\n');
        return sb.ToString();
    }

    public static Envelope Parse(string text)
    {
        var e = new Envelope();
        // Normalize newlines so CRLF-saved files parse the same as LF.
        text = text.Replace("\r\n", "\n").Replace('\r', '\n');
        var lines = text.Split('\n');
        int i = 0;
        if (i < lines.Length && lines[i].Trim() == "---")
        {
            i++;
            for (; i < lines.Length && lines[i].Trim() != "---"; i++)
            {
                int c = lines[i].IndexOf(':');
                if (c <= 0) continue;
                string key = lines[i][..c].Trim().ToLowerInvariant();
                string val = lines[i][(c + 1)..].Trim();
                switch (key)
                {
                    case "id": e.Id = val; break;
                    case "from": e.From = val; break;
                    case "to": e.To = val; break;
                    case "subject": e.Subject = val; break;
                    case "reply_to": e.ReplyTo = val; break;
                    case "sent": e.Sent = val; break;
                }
            }
            if (i < lines.Length) i++; // skip closing ---
        }
        e.Body = string.Join('\n', lines.Skip(i)).Trim();
        return e;
    }
}
