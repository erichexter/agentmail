namespace AgentMail.Crypto;

/// <summary>
/// Crockford base32 — 0123456789ABCDEFGHJKMNPQRSTVWXYZ — uppercase, unpadded.
///
/// Digits-first: 0-9 then A-Z excluding I, L, O, U. This is NOT RFC 4648's alphabet (A-Z then 2-7); deriving
/// it as "RFC 4648 minus I/L/O/U" gives 28 symbols, not 32, and no digits. The distinction matters because
/// these characters land in signed bytes.
///
/// Used for two distinct things, both of which land in signed bytes, so the alphabet is part of the wire
/// contract and vectors pin it:
///   - ULID msg_id            — 128 bits → 26 chars
///   - *_key_id fingerprints  — base32(sha256(pubkey)), 256 bits → 52 chars, no truncation (FLAG-40)
/// </summary>
static class Base32
{
    const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   // Crockford: no I, L, O, U

    /// <summary>Encode big-endian, 5 bits per character, unpadded. 32 bytes → 52 chars.</summary>
    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return "";
        int outLen = (data.Length * 8 + 4) / 5;
        var chars = new char[outLen];
        int bitBuffer = 0, bitCount = 0, o = 0;

        foreach (byte b in data)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitCount += 8;
            while (bitCount >= 5)
            {
                bitCount -= 5;
                chars[o++] = Alphabet[(bitBuffer >> bitCount) & 0x1F];
            }
        }
        if (bitCount > 0) chars[o++] = Alphabet[(bitBuffer << (5 - bitCount)) & 0x1F];   // pad low bits with zeros

        return new string(chars, 0, o);
    }

    /// <summary>
    /// Fingerprint of a public key: base32(sha256(pubkey)) — the FULL digest, N=52 chars, never truncated.
    ///
    /// FLAG-40: the full 256-bit digest gives ~128-bit collision resistance and removes the lookup-ambiguity
    /// and grinding surface a short N would open. A shorter form is display-only and MUST NOT change this
    /// on-wire, AD-signed value.
    ///
    /// This is NOT interchangeable with the raw public key. The X3DH transcript consumes RAW 32-byte pubkeys;
    /// only the two trailing transcript fields are these fingerprints. Swapping them silently desyncs SK, so a
    /// vector pins the failure.
    /// </summary>
    public static string KeyId(ReadOnlySpan<byte> publicKey) => Encode(Primitives.Sha256(publicKey));
}
