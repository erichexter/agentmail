using System.Buffers.Binary;
using System.Text;
using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// The pre-image bytes ARE the signature. These tests are the gate, not review.
///
/// Covers the three FLAG-27 TLV traps the brief says an implementer WILL get wrong, each with an explicit
/// accept AND reject, plus the content_hash encoding Wolf ruled on 2026-07-16 (App C wins: field()-wrapped).
/// </summary>
public class PreImageTests
{
    static SealedEnvelope Env()
    {
        var e = new SealedEnvelope
        {
            MsgId = "01J000000000000000000000AB",
            ProtocolVersion = 1,
            From = new Address("wolf", "gateway"),
            To = new Address("smiley", "acer-desktop"),
            ContentType = "text/markdown",
            Size = 48,
            CreatedAt = 1752700000000,
            ExpiresAt = 1752786400000,
            Priority = Priority.Normal,
            WantReceipt = true,
            RequireE2e = false,
            Ordered = false,
            Fanout = false,
            ContentHash = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
            Enc = new EncMeta
            {
                Mode = EncMode.Enc,
                SenderKeyId = new string('A', 52),
                RecipientKeyId = new string('B', 52),
                KeyEpoch = 3,
                SpkEpoch = 0,
                OpkId = 0,
                Nonce = new byte[Primitives.AeadNonceSize],
                EphPub = new byte[Primitives.X25519PublicKeySize],
            },
            Auth = new AuthMeta { KeyId = new string('A', 52), KeyEpoch = 3 },
        };
        return e;
    }

    // --- P0-A: the cycle-break -------------------------------------------------------------------

    [Fact]
    public void AeadAd_does_not_contain_content_hash_so_it_is_computable_before_the_ciphertext_exists()
    {
        var e = Env();
        byte[] adWithHash = PreImage.AeadAdV1(e);

        e.ContentHash = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        byte[] adOtherHash = PreImage.AeadAdV1(e);

        // Changing content_hash must not move aead_ad at all — that is the whole point of P0-A. If this ever
        // fails, the seal is uncomputable: AD would depend on a hash of the ciphertext that AD produces.
        Assert.Equal(Convert.ToHexString(adWithHash), Convert.ToHexString(adOtherHash));
    }

    [Fact]
    public void SignInput_and_AeadAd_use_different_domain_separation_prefixes()
    {
        var e = Env();
        Assert.StartsWith("agentmail/v1/aead-ad", Encoding.ASCII.GetString(PreImage.AeadAdV1(e))[5..]);
        Assert.StartsWith("agentmail/v1/preimage", Encoding.ASCII.GetString(PreImage.SignInputV1(e))[5..]);
    }

    [Fact]
    public void SignInput_differs_from_AeadAd_by_exactly_the_wrapped_content_hash()
    {
        var e = Env();
        // 37 bytes = 0x01 ‖ be32(32) ‖ 32 raw — plus the DS prefix length delta between the two tags.
        int tagDelta = "agentmail/v1/preimage".Length - "agentmail/v1/aead-ad".Length;
        Assert.Equal(PreImage.AeadAdV1(e).Length + 37 + tagDelta, PreImage.SignInputV1(e).Length);
    }

    // --- FLAG-27.1 (RULED 2026-07-16: App C wins) ------------------------------------------------

    [Fact]
    public void ACCEPT_content_hash_is_field_wrapped_over_its_raw_32_bytes()
    {
        // App C line 997: field(1, content_hash_raw32) = 0x01 ‖ be32(32) ‖ <32 raw bytes>.
        var e = Env();
        byte[] p = PreImage.SignInputV1(e);

        var expected = new byte[37];
        expected[0] = 0x01;
        BinaryPrimitives.WriteUInt32BigEndian(expected.AsSpan(1), 32);
        e.ContentHash!.CopyTo(expected, 5);

        Assert.Contains(Convert.ToHexString(expected), Convert.ToHexString(p));
    }

    [Fact]
    public void REJECT_a_the_same_32_bytes_unwrapped_yields_a_different_pre_image()
    {
        // The pre-spike brief said content_hash was NOT field()-wrapped. It is. This pins that the unwrapped
        // form is a DIFFERENT pre-image, so an implementation that skips the wrapper fails interop loudly
        // rather than producing quietly-invalid signatures.
        var e = Env();
        byte[] correct = PreImage.SignInputV1(e);
        byte[] unwrapped = SignInputWithRawContentHash(e);
        Assert.NotEqual(Convert.ToHexString(correct), Convert.ToHexString(unwrapped));
        Assert.Equal(correct.Length - 5, unwrapped.Length);   // missing 0x01 ‖ be32(32)
    }

    [Fact]
    public void REJECT_b_the_hex_string_field_wrapped_yields_a_different_pre_image()
    {
        // "raw-32" means the 32 DECODED bytes, not the 64-char hex string the JSON carries. Feeding the hex
        // through is the other half of the misread and must not silently verify.
        var e = Env();
        byte[] correct = PreImage.SignInputV1(e);
        byte[] hexWrapped = SignInputWithHexContentHash(e);
        Assert.NotEqual(Convert.ToHexString(correct), Convert.ToHexString(hexWrapped));
        Assert.Equal(correct.Length + 32, hexWrapped.Length);  // 64 ASCII bytes instead of 32 raw
    }

    // --- FLAG-27.2: absent #session emits 0x00, it is not omitted --------------------------------

    [Fact]
    public void Absent_session_emits_a_presence_byte_rather_than_being_omitted()
    {
        using var without = new MemoryStream();
        PreImage.Addr(without, new Address("wolf", "gateway"));

        using var with = new MemoryStream();
        PreImage.Addr(with, new Address("wolf", "gateway", "s1"));

        // name + host fields are identical; the difference is a bare 0x00 vs field(1,"s1") = 0x01‖be32(2)‖"s1".
        Assert.Equal(0x00, without.ToArray()[^1]);
        Assert.Equal(without.ToArray().Length + 6, with.ToArray().Length);
    }

    // --- FLAG-27.3: reply_to is the ONLY top-level field where 0x00 is legal ----------------------

    [Fact]
    public void Null_reply_to_is_legal_and_emits_a_single_zero_presence_byte()
    {
        var e = Env();
        e.ReplyTo = null;
        byte[] withoutReplyTo = PreImage.SignInputV1(e);

        e.ReplyTo = new Address("wolf", "gateway");
        byte[] withReplyTo = PreImage.SignInputV1(e);

        Assert.True(withReplyTo.Length > withoutReplyTo.Length);
    }

    [Fact]
    public void reply_to_pointing_at_a_third_party_host_is_rejected()
    {
        // FLAG-45: without this, reply_to is a reply-redirection primitive. It is signed, so the check is
        // structural rather than heuristic.
        var e = Env();
        e.ReplyTo = new Address("attacker", "evil-host");
        var ex = Assert.Throws<NonConformingFieldException>(() => PreImage.SignInputV1(e));
        Assert.Equal("reply_to", ex.Field);
    }

    // --- Ingress: reject, never normalize (P2-K / FLAG-6) ----------------------------------------

    [Theory]
    [InlineData("Wolf")]        // uppercase — lowercasing is a MINT concern, never a silent fold here
    [InlineData("-wolf")]       // leading hyphen
    [InlineData("wolf-")]       // trailing hyphen
    [InlineData("wolf_x")]      // underscore is not LDH
    [InlineData("wolf.gw")]     // dot is not LDH
    [InlineData("")]
    public void Non_LDH_names_are_rejected_not_normalized(string name)
    {
        var e = Env();
        e.From = new Address(name, "gateway");
        Assert.Throws<NonConformingFieldException>(() => PreImage.SignInputV1(e));
    }

    [Fact]
    public void ordered_true_is_rejected_as_an_unsupported_capability()
    {
        // FLAG-22: with no ratchet there is no sequence state, so nothing in PR1–PR4 can enforce ordering.
        // Reserved rather than quietly accepted-and-ignored.
        var e = Env();
        e.Ordered = true;
        Assert.Throws<NonConformingFieldException>(() => PreImage.SignInputV1(e));
    }

    [Fact]
    public void content_type_allow_list_is_versioned_by_protocol_version_not_node_local()
    {
        // FLAG-44: a content_type valid at protocol_version=1 must be accepted by every v>=1 node, so benign
        // version skew never becomes delivery loss.
        Assert.True(ContentTypes.IsRegistered("text/markdown", 1));
        Assert.True(ContentTypes.IsRegistered("text/markdown", 2));
        Assert.False(ContentTypes.IsRegistered("application/x-made-up", 1));
    }

    [Fact]
    public void key_selection_fields_are_all_inside_the_signed_pre_image()
    {
        // A transit flip of any of these must be a clean structural signature failure, not a decrypt oracle.
        var e = Env();
        byte[] baseline = PreImage.SignInputV1(e);

        foreach (var mutate in new Action<SealedEnvelope>[]
        {
            x => x.Enc.KeyEpoch++,
            x => x.Enc.SpkEpoch++,
            x => x.Enc.OpkId++,
            x => x.Enc.SenderKeyId = new string('C', 52),
            x => x.Enc.RecipientKeyId = new string('D', 52),
            x => x.Enc.Nonce = Enumerable.Repeat((byte)1, Primitives.AeadNonceSize).ToArray(),
            x => x.Enc.EphPub = Enumerable.Repeat((byte)1, Primitives.X25519PublicKeySize).ToArray(),
            x => x.Auth.KeyEpoch++,
            x => x.WantReceipt = !x.WantReceipt,
            x => x.RequireE2e = !x.RequireE2e,
            x => x.Fanout = !x.Fanout,
        })
        {
            var m = Env();
            mutate(m);
            Assert.NotEqual(Convert.ToHexString(baseline), Convert.ToHexString(PreImage.SignInputV1(m)));
        }
    }

    // --- helpers that build the REJECTED variants, so the tests compare against something real ----

    static byte[] SignInputWithRawContentHash(SealedEnvelope e)
    {
        byte[] full = PreImage.SignInputV1(e);
        int at = IndexOfWrappedHash(full, e.ContentHash!);
        var outp = new byte[full.Length - 5];
        full.AsSpan(0, at).CopyTo(outp);
        full.AsSpan(at + 5).CopyTo(outp.AsSpan(at));
        return outp;
    }

    static byte[] SignInputWithHexContentHash(SealedEnvelope e)
    {
        byte[] full = PreImage.SignInputV1(e);
        int at = IndexOfWrappedHash(full, e.ContentHash!);
        byte[] hex = Encoding.ASCII.GetBytes(Convert.ToHexString(e.ContentHash!).ToLowerInvariant());

        using var ms = new MemoryStream();
        ms.Write(full.AsSpan(0, at));
        PreImage.Field(ms, true, hex);
        ms.Write(full.AsSpan(at + 37));
        return ms.ToArray();
    }

    static int IndexOfWrappedHash(byte[] haystack, byte[] hash)
    {
        var needle = new byte[37];
        needle[0] = 0x01;
        BinaryPrimitives.WriteUInt32BigEndian(needle.AsSpan(1), 32);
        hash.CopyTo(needle, 5);

        for (int i = 0; i + needle.Length <= haystack.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle)) return i;
        throw new InvalidOperationException("wrapped content_hash not found in pre-image");
    }
}
