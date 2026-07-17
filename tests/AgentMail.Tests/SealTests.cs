using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// End-to-end PR1 seal/open, plus the traps that only show up when real bytes move.
/// Each test runs against a throwaway AGENTMAIL_ROOT so it never touches a real agent's keys.
/// </summary>
public class SealTests
{
    // AGENTMAIL_ROOT is redirected to a temp dir by TestRoot's module initializer, before Paths.Root is ever
    // read. Identities are per-test-unique so parallel tests cannot collide on the same key file.
    readonly string _tag = Guid.NewGuid().ToString("N")[..8];

    (Identity sender, Identity recipient) Pair() =>
        (Id($"wolf-{_tag}", "gateway"), Id($"smiley-{_tag}", "acer-desktop"));

    static Identity Id(string name, string host) => Identity.LoadOrCreate(new Address(name, host));

    [Fact]
    public void Seal_then_open_round_trips_the_exact_plaintext()
    {
        var (sender, recipient) = Pair();
        byte[] plaintext = "the quick brown fox"u8.ToArray();

        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AB", plaintext);

        Assert.Equal(plaintext, Seal.Open(recipient, e, sender.PublicKey));
    }

    [Fact]
    public void A_binary_body_whose_real_trailing_bytes_are_zero_still_round_trips()
    {
        // FLAG-41: this is why padding is self-describing. Zero-padding a body that legitimately ENDS in 0x00
        // is unrecoverable without the inner length prefix — you cannot tell payload from padding.
        var (sender, recipient) = Pair();
        byte[] plaintext = [0x01, 0x02, 0x00, 0x00, 0x00];

        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AC", plaintext);

        Assert.Equal(plaintext, Seal.Open(recipient, e, sender.PublicKey));
    }

    [Fact]
    public void Padding_round_trips_at_a_bucket_boundary_and_preserves_trailing_zeros()
    {
        byte[] pt = [0xAA, 0x00, 0x00];
        byte[] padded = Seal.Pad(pt, bucket: 64);
        Assert.Equal(64, padded.Length);
        Assert.Equal(pt, Seal.Unpad(padded));
    }

    [Fact]
    public void size_and_content_hash_cover_the_FINAL_post_padding_on_wire_bytes()
    {
        // FLAG-23: both are over the post-padding ciphertext, never the pre-pad plaintext length.
        var (sender, recipient) = Pair();
        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AD", "hello"u8.ToArray());

        Assert.Equal((uint)e.Body.Length, e.Size);
        Assert.Equal(Convert.ToHexString(Primitives.Sha256(e.Body)), Convert.ToHexString(e.ContentHash!));
    }

    [Fact]
    public void A_flipped_nonce_is_a_structural_signature_failure_not_a_decrypt_oracle()
    {
        // nonce and eph_pub are in BOTH pre-images precisely so a tampering relay trips the signature check
        // rather than handing the recipient a decrypt failure it could be goaded into bouncing on.
        var (sender, recipient) = Pair();
        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AE", "hello"u8.ToArray());

        e.Enc.Nonce[0] ^= 0xFF;

        var ex = Assert.Throws<VerifyFailedException>(() => Seal.Open(recipient, e, sender.PublicKey));
        Assert.Contains("agent_sig", ex.Message);
    }

    [Fact]
    public void A_tampered_body_fails_content_hash_before_any_decrypt_is_attempted()
    {
        var (sender, recipient) = Pair();
        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AF", "hello"u8.ToArray());

        e.Body[0] ^= 0xFF;

        var ex = Assert.Throws<VerifyFailedException>(() => Seal.Open(recipient, e, sender.PublicKey));
        Assert.Contains("content_hash", ex.Message);
    }

    [Fact]
    public void An_envelope_signed_by_a_different_key_than_the_pin_is_rejected()
    {
        // FLAG-8b: with no CA, the pin IS the trust root. A self-signed record must never substitute itself.
        var (sender, recipient) = Pair();
        var impostor = Id($"impostor-{_tag}", "evil-host");

        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AG", "hello"u8.ToArray());

        Assert.Throws<VerifyFailedException>(() => Seal.Open(recipient, e, impostor.PublicKey));
    }

    [Fact]
    public void A_sealed_body_cannot_be_transplanted_onto_another_recipients_envelope()
    {
        // FLAG-25 / P0-A: AD binds to{name,host} and recipient_key_id, so reusing A's blob against B's key
        // must AEAD-fail. Do NOT "fix" a failure here by dropping `to` from the AD.
        var (sender, recipientA) = Pair();
        var recipientB = Id($"gus-{_tag}", "services-vm");

        var toA = Seal.Create(sender, recipientA.Address, recipientA.PublicKey, recipientA.KeyEpoch,
                              "01J000000000000000000000AH", "for A"u8.ToArray());
        var toB = Seal.Create(sender, recipientB.Address, recipientB.PublicKey, recipientB.KeyEpoch,
                              "01J000000000000000000000AH", "for B"u8.ToArray());

        // Same logical msg_id, two recipients ⇒ two independent seals with distinct AD/SK/nonce/content_hash.
        Assert.NotEqual(Convert.ToHexString(toA.ContentHash!), Convert.ToHexString(toB.ContentHash!));
        Assert.NotEqual(Convert.ToHexString(toA.Enc.Nonce), Convert.ToHexString(toB.Enc.Nonce));
        Assert.NotEqual(toA.SealKey, toB.SealKey);   // seal-cache key is (msg_id, to), never msg_id alone

        toB.Body = toA.Body;
        Assert.Throws<VerifyFailedException>(() => Seal.Open(recipientB, toB, sender.PublicKey));
    }

    [Fact]
    public void The_interim_PR1_seal_signals_identity_only_via_spk_epoch_and_opk_id_zero()
    {
        // FLAG-4: PR1's seal is a staging construct. The recipient's SK-subset rule reads exactly these two
        // SIGNED fields, which is what lets PR1 and PR2 envelopes coexist on the wire.
        var (sender, recipient) = Pair();
        var e = Seal.Create(sender, recipient.Address, recipient.PublicKey, recipient.KeyEpoch,
                            "01J000000000000000000000AJ", "hello"u8.ToArray());

        Assert.Equal(0u, e.Enc.SpkEpoch);
        Assert.Equal(0u, e.Enc.OpkId);
        Assert.Equal(EncMode.Enc, e.Enc.Mode);
    }

    [Fact]
    public void Transcript_rejects_a_key_id_fingerprint_where_a_raw_public_key_belongs()
    {
        // FLAG-40: the *_pub fields are RAW 32-byte keys; only the two trailing fields are base32 fingerprints.
        // The names invite a swap, and a swap silently desyncs SK — so pin that they produce different bytes.
        byte[] pub = Primitives.RandomBytes(32);
        string keyId = Base32.KeyId(pub);

        byte[] correct = PreImage.Transcript(pub, pub, [], [], pub, 1, 0, 0, keyId, keyId);
        byte[] swapped = PreImage.Transcript(System.Text.Encoding.ASCII.GetBytes(keyId)[..32], pub, [], [], pub,
                                             1, 0, 0, keyId, keyId);

        Assert.NotEqual(Convert.ToHexString(correct), Convert.ToHexString(swapped));
    }
}
