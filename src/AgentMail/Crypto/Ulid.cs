using System.Text.Json;

namespace AgentMail.Crypto;

/// <summary>
/// ULID minter: 48-bit big-endian millisecond timestamp + 80 bits of randomness, Crockford base32, 26 chars.
/// Time-ordered, so msg_ids sort by mint time.
///
/// FLAG-48 — the requirement is CLOCK-REGRESSION SAFETY, not counter persistence.
///
/// The timestamp is the HIGH-ORDER part of a ULID, so persisting a counter alone does not help: if the wall
/// clock steps backward (an NTP correction) a naive minter emits a smaller — potentially colliding — id than
/// one already issued, no matter what the counter says. Framing it as clock-regression safety rather than
/// counter persistence is the whole point of the flag.
///
/// So we persist the high-water (timestamp, random) pair and mint monotonically:
///   now &gt; last   → take the clock, fresh randomness
///   now &lt;= last  → hold the high-water timestamp and INCREMENT the 80-bit random field (with carry)
///
/// Incrementing the random field — not a side counter — is what makes same-millisecond ids strictly ordered,
/// because the random field is the low-order part of the id. On carry overflow we advance the synthetic
/// timestamp by 1ms; the real clock overtakes it once it catches up.
/// </summary>
sealed class Ulid
{
    const int TimestampBytes = 6;    // 48 bits of ms — good to the year 10889
    const int RandomBytes = 10;      // 80 bits
    const int EncodedLength = 26;

    readonly string _statePath;
    readonly object _gate = new();
    long _lastMs;
    byte[] _lastRandom = new byte[RandomBytes];

    public Ulid(string statePath)
    {
        _statePath = statePath;
        (_lastMs, _lastRandom) = LoadHighWater();
    }

    /// <summary>Mint the next id. Thread-safe.</summary>
    public string Next() => Next(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    /// <summary>Mint against an explicit clock reading. Exists so tests can drive a clock regression.</summary>
    internal string Next(long nowMs)
    {
        long ms;
        byte[] random;

        lock (_gate)
        {
            if (nowMs > _lastMs)
            {
                ms = nowMs;
                random = new byte[RandomBytes];
                Primitives.FillRandom(random);
            }
            else
            {
                // Same millisecond, or the clock stepped BACKWARD. Both are handled identically: hold the
                // high-water timestamp and increment the random field so the id still ascends.
                ms = _lastMs;
                random = (byte[])_lastRandom.Clone();
                if (!IncrementWithCarry(random))
                {
                    // 2^80 ids in one millisecond is not reachable in practice, but overflow must not wrap into
                    // a smaller id. Carry into a synthetic future millisecond instead.
                    ms = _lastMs + 1;
                    Primitives.FillRandom(random);
                }
            }

            _lastMs = ms;
            _lastRandom = random;
            PersistHighWater(ms, random);
        }

        Span<byte> raw = stackalloc byte[TimestampBytes + RandomBytes];
        for (int i = 0; i < TimestampBytes; i++) raw[i] = (byte)(ms >> (8 * (TimestampBytes - 1 - i)));
        random.CopyTo(raw[TimestampBytes..]);

        string s = Base32.Encode(raw);
        return s.Length > EncodedLength ? s[..EncodedLength] : s.PadLeft(EncodedLength, '0');
    }

    /// <summary>Big-endian increment. False on overflow (all 0xFF).</summary>
    static bool IncrementWithCarry(byte[] value)
    {
        for (int i = value.Length - 1; i >= 0; i--)
            if (++value[i] != 0) return true;    // no carry out of this byte ⇒ done
        return false;
    }

    sealed record HighWater(long LastMs, string LastRandom);

    (long, byte[]) LoadHighWater()
    {
        try
        {
            if (!File.Exists(_statePath)) return (0, Fresh());
            var hw = JsonSerializer.Deserialize<HighWater>(File.ReadAllText(_statePath), Paths.Json);
            if (hw is null) return (0, Fresh());
            byte[] r = Convert.FromBase64String(hw.LastRandom);
            return (hw.LastMs, r.Length == RandomBytes ? r : Fresh());
        }
        catch
        {
            // Unreadable/corrupt state. Fall back to the current clock rather than 0: starting from 0 would make
            // every mint look like a regression and jam every id into the increment path. The exposure after
            // corruption is the same one a fresh install has — no regression protection for ids minted before it.
            return (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), Fresh());
        }

        static byte[] Fresh() { var b = new byte[RandomBytes]; Primitives.FillRandom(b); return b; }
    }

    void PersistHighWater(long ms, byte[] random)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            Io.WriteAtomic(_statePath, JsonSerializer.Serialize(new HighWater(ms, Convert.ToBase64String(random)), Paths.Json));
        }
        catch
        {
            // Best-effort: a mint must not fail because the high-water file is momentarily unwritable. The
            // in-memory mark still protects this process; a crash before persist only loses protection across a
            // restart, and only if the clock also steps back.
        }
    }
}
