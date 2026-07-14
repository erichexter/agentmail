namespace AgentMail;

/// <summary>Minimal, dependency-free argument parser: `verb --key value --flag`.</summary>
sealed class Cli
{
    public string Verb { get; }
    private readonly Dictionary<string, string> _opts = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);

    private Cli(string verb) => Verb = verb;

    public static Cli Parse(string[] argv)
    {
        var cli = new Cli(argv.Length > 0 ? argv[0].ToLowerInvariant() : "");
        for (int i = 1; i < argv.Length; i++)
        {
            string a = argv[i];
            if (!a.StartsWith("--")) continue;
            string key = a[2..];
            // A value follows unless we're at the end or the next token is another option.
            if (i + 1 < argv.Length && !argv[i + 1].StartsWith("--"))
            {
                cli._opts[key] = argv[++i];
            }
            else
            {
                cli._flags.Add(key);
            }
        }
        return cli;
    }

    public string? Get(string name) => _opts.TryGetValue(name, out var v) ? v : null;
    public bool Has(string name) => _flags.Contains(name) || _opts.ContainsKey(name);

    public string Require(string name) =>
        Get(name) ?? throw new CliError($"missing required --{name}");
}

sealed class CliError(string message) : Exception(message);

/// <summary>Split "agent@host" into its parts; host is null when omitted (local).</summary>
static class AgentRef
{
    public static (string name, string? host) Split(string reference)
    {
        int at = reference.IndexOf('@');
        return at < 0
            ? (reference.Trim(), null)
            : (reference[..at].Trim(), reference[(at + 1)..].Trim().ToLowerInvariant());
    }
}
