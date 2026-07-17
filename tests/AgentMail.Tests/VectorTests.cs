using System.Text.Json;
using System.Text.Json.Nodes;
using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// The cross-implementation conformance gate. The PRD's rule is "no hub ships until it reproduces every vector
/// byte-for-byte", so these are the contract — not the C# implementation, which is just the first thing to
/// satisfy them.
///
/// Vectors live in tests/vectors/*.json with fixed keys, so a reimplementation in another language can consume
/// them without reading any C#. Regenerate with AGENTMAIL_REGEN_VECTORS=1 — and if a diff appears that you did
/// not intend, that is the gate doing its job. Do not regenerate to make a failure go away.
/// </summary>
public class VectorTests
{
    static readonly string VectorDir =
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "vectors");

    static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    /// <summary>Fully deterministic envelope — no randomness, no clock — so the vector is reproducible.</summary>
    static SealedEnvelope FixedEnvelope() => new()
    {
        MsgId = "01J000000000000000000000AB",
        ProtocolVersion = 1,
        From = new Address("wolf", "gateway"),
        To = new Address("smiley", "acer-desktop"),
        ReplyTo = null,
        ContentType = "text/markdown",
        Size = 48,
        ContentHash = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
        CreatedAt = 1752700000000,
        ExpiresAt = 1752786400000,
        Priority = Priority.Normal,
        WantReceipt = true,
        RequireE2e = false,
        Ordered = false,
        Fanout = false,
        Enc = new EncMeta
        {
            Mode = EncMode.Enc,
            SenderKeyId = new string('A', 52),
            RecipientKeyId = new string('B', 52),
            KeyEpoch = 3,
            SpkEpoch = 0,
            OpkId = 0,
            Nonce = Enumerable.Range(0, 24).Select(i => (byte)(0x40 + i)).ToArray(),
            EphPub = Enumerable.Range(0, 32).Select(i => (byte)(0x80 + i)).ToArray(),
        },
        Auth = new AuthMeta { KeyId = new string('A', 52), KeyEpoch = 3 },
    };

    [Fact]
    public void Envelope_pre_images_match_the_committed_vector()
    {
        var e = FixedEnvelope();

        var actual = new JsonObject
        {
            ["_comment"] = "PRD Appendix C (normative). Both variants. Byte-for-byte conformance gate — see §5.1/§5.3.",
            ["ds_aead_prefix"] = PreImage.DsAeadPrefix,
            ["ds_auth_prefix"] = PreImage.DsAuthPrefix,
            ["ds_auth"] = PreImage.DsAuth,
            ["version_byte"] = PreImage.VersionByte,
            ["content_hash_encoding"] =
                "field(1, content_hash_raw32) = 0x01 || be32(32) || <32 raw bytes>. In sign_input_v1 ONLY, "
                + "never aead_ad_v1 (P0-A). 'raw-32' = the 32 DECODED bytes, NOT the 64-char hex string — "
                + "and NOT unwrapped. Ruled 2026-07-16: App C wins over the brief's earlier FLAG-27.1 text.",
            ["envelope"] = JsonNode.Parse(JsonSerializer.Serialize(e, Paths.Json)),
            ["aead_ad_v1"] = Hex(PreImage.AeadAdV1(e)),
            ["sign_input_v1"] = Hex(PreImage.SignInputV1(e)),
        };

        AssertMatchesVector("envelope-preimages.json", actual);
    }

    [Fact]
    public void Rejected_content_hash_encodings_match_the_committed_vector()
    {
        // The two forms an implementer plausibly builds instead. Pinned so a reimplementation can assert it
        // does NOT produce them — a reject vector is only useful if the wrong bytes are written down.
        var e = FixedEnvelope();
        byte[] correct = PreImage.SignInputV1(e);

        var actual = new JsonObject
        {
            ["_comment"] = "REJECT vectors for content_hash. Both are DIFFERENT pre-images from sign_input_v1 "
                         + "and MUST NOT verify. Ruled 2026-07-16 (App C wins).",
            ["accept_sign_input_v1"] = Hex(correct),
            ["reject_a_unwrapped_raw32"] = Hex(RejectUnwrapped(e)),
            ["reject_a_why"] = "the same 32 bytes with no 0x01||be32(32) prefix — the pre-spike FLAG-27.1 reading",
            ["reject_b_hex_string_field_wrapped"] = Hex(RejectHexWrapped(e)),
            ["reject_b_why"] = "field(1, <64 ASCII hex bytes>) — treats 'raw-32' as the hex string the JSON carries",
        };

        AssertMatchesVector("content-hash-reject.json", actual);
    }

    [Fact]
    public void Rfc7748_and_hkdf_primitives_match_the_committed_vector()
    {
        byte[] alicePriv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPub = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] ikm = Enumerable.Range(0, 128).Select(i => (byte)i).ToArray();

        var actual = new JsonObject
        {
            ["_comment"] = "Primitive KATs. X25519 must be RAW scalarmult (a KDF'd output cannot reproduce "
                         + "RFC 7748 §6.1). KDF is unconditionally BCL HKDF-SHA256, salt = 32×0x00 (FLAG-8a).",
            ["x25519_rfc7748_6_1_shared"] = Hex(Primitives.X25519Dh(alicePriv, bobPub)),
            ["hkdf_salt"] = Hex(new byte[32]),
            ["hkdf_info"] = PreImage.DsX3dh,
            ["hkdf_ikm_128_counting_bytes"] = Hex(ikm),
            ["hkdf_out_32"] = Hex(Primitives.Hkdf(ikm, System.Text.Encoding.ASCII.GetBytes(PreImage.DsX3dh))),
        };

        AssertMatchesVector("primitives.json", actual);
    }

    [Fact]
    public void AgentCertLite_pre_image_matches_the_committed_vector()
    {
        // The PR1 TOFU record. Identity-only reduction of App C's sign_input_agentcert (not_after/issuer_id
        // OMITTED — PR3 fields with no CA in PR1). Flagged to Wolf; pinned here so a reimplementation matches.
        var record = new AgentCertLite
        {
            Addr = new Address("wolf", "gateway"),
            IdentPub = Enumerable.Range(0, 32).Select(i => (byte)(0xC0 + i)).ToArray(),
            KeyEpoch = 3,
            RecordEpoch = 7,
        };

        // The full CA-issued AgentCert over the SAME identity fields — built only to prove the lite pin differs
        // from it. A PR3 verifier chains this to a root; a PR1 verifier pin-checks the lite record. Same identity,
        // two objects, two pre-images.
        byte[] full = PreImage.SignInputAgentCertFull(
            record.Addr, record.IdentPub, record.KeyEpoch, notAfter: 1893456000000, record.RecordEpoch, issuerId: "hex-root");
        byte[] lite = PreImage.SignInputAgentCertLite(record);

        var actual = new JsonObject
        {
            ["_comment"] = "PR1 self-signed TOFU pin (brief PR1.3). A DIFFERENT object from the CA-issued "
                         + "AgentCert (Wolf's ruling 2026-07-17), NOT a reduced form: it has its own DS tag and "
                         + "omits the CA-issuance fields (not_after, issuer_id) because a self-signed pin has no "
                         + "CA. DS_AGENTCERT_LITE tag-namespace addition routed to Harrell for App C.",
            ["ds_agent_cert_lite"] = PreImage.DsAgentCertLite,
            ["ds_agent_cert_full_ca"] = PreImage.DsAgentCert,
            ["accept_sign_input_agentcert_lite"] = Hex(lite),
            ["reject_full_ca_agentcert_same_identity"] = Hex(full),
            ["reject_why"] = "the CA AgentCert over the same addr/ident_pub/key_epoch/record_epoch — different "
                           + "DS tag AND different field set, so a non-matching pre-image. A lite pin MUST NOT "
                           + "verify as an AgentCert and vice versa; that boundary is what PR3 dual-trust relies on.",
        };

        // The object boundary, asserted: same identity, provably distinct signed bytes.
        Assert.NotEqual(Convert.ToHexString(lite), Convert.ToHexString(full));

        AssertMatchesVector("agentcert-lite-preimage.json", actual);
    }

    [Fact]
    public void KeysFetch_pre_image_matches_the_committed_vector()
    {
        // Signed GET /keys request (brief PR1.4). A cross-implementation contract — another agent's fetch must
        // reconstruct these exact bytes for the relay to authenticate it.
        var actual = new JsonObject
        {
            ["_comment"] = "SignInputKeysFetch = DS_KEYS_FETCH || u8(1) || addr(requester) || addr(target) || "
                         + "field(1,be64(requested_at)). Authenticates a key fetch to the fetcher's identity, "
                         + "not the shared bearer token. DS_KEYS_FETCH routed to Harrell for App C.",
            ["ds_keys_fetch"] = PreImage.DsKeysFetch,
            ["sign_input_keys_fetch"] = Hex(PreImage.SignInputKeysFetch(
                new Address("smiley", "acer-desktop"), new Address("wolf", "gateway"), 1752700000000)),
        };
        AssertMatchesVector("keys-fetch-preimage.json", actual);
    }

    [Fact]
    public void Receipt_pre_image_matches_the_committed_vector()
    {
        var actual = new JsonObject
        {
            ["_comment"] = "receipt_v1 (FLAG-28). Receipts are signed envelopes: binding orig_msg_id AND "
                         + "orig_content_hash stops a receipt being replayed onto a different message.",
            ["ds_receipt"] = PreImage.DsReceipt,
            ["receipt_v1_consumed"] = Hex(PreImage.ReceiptV1(
                "01J000000000000000000000AB",
                Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
                ReceiptType.Consumed,
                1752700001000,
                new Address("smiley", "acer-desktop"),
                new Address("wolf", "gateway"))),
        };

        AssertMatchesVector("receipt-preimage.json", actual);
    }

    // --- helpers ----------------------------------------------------------------------------------

    static void AssertMatchesVector(string fileName, JsonObject actual)
    {
        Directory.CreateDirectory(VectorDir);
        string path = Path.Combine(VectorDir, fileName);
        string rendered = actual.ToJsonString(Pretty);

        if (Environment.GetEnvironmentVariable("AGENTMAIL_REGEN_VECTORS") == "1" || !File.Exists(path))
        {
            File.WriteAllText(path, rendered + "\n");
            return;
        }

        Assert.Equal(File.ReadAllText(path).TrimEnd('\n'), rendered);
    }

    static byte[] RejectUnwrapped(SealedEnvelope e)
    {
        byte[] full = PreImage.SignInputV1(e);
        int at = FindWrappedHash(full, e.ContentHash!);
        var o = new byte[full.Length - 5];
        full.AsSpan(0, at).CopyTo(o);
        full.AsSpan(at + 5).CopyTo(o.AsSpan(at));
        return o;
    }

    static byte[] RejectHexWrapped(SealedEnvelope e)
    {
        byte[] full = PreImage.SignInputV1(e);
        int at = FindWrappedHash(full, e.ContentHash!);
        byte[] hex = System.Text.Encoding.ASCII.GetBytes(Hex(e.ContentHash!));

        using var ms = new MemoryStream();
        ms.Write(full.AsSpan(0, at));
        PreImage.Field(ms, true, hex);
        ms.Write(full.AsSpan(at + 37));
        return ms.ToArray();
    }

    static int FindWrappedHash(byte[] haystack, byte[] hash)
    {
        var needle = new byte[37];
        needle[0] = 0x01;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(needle.AsSpan(1), 32);
        hash.CopyTo(needle, 5);
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle)) return i;
        throw new InvalidOperationException("wrapped content_hash not found");
    }
}
