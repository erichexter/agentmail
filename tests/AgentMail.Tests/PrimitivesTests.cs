using System.Security.Cryptography;
using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// Pins the FLAG-8 spike outcome in CI so a library bump cannot silently regress it.
///
/// The spike (2026-07-16, gate PASS) established that Geralt's ComputeSharedSecret is raw, un-KDF'd X25519.
/// That is not a property you can eyeball — the KDF'd helper sits right next to it with a nearly identical
/// name and returns the same-shaped 32 bytes. Only a known-answer test distinguishes them.
/// </summary>
public class PrimitivesTests
{
    // RFC 7748 §6.1 — the decisive vector. A KDF'd output cannot reproduce it.
    const string AlicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const string AlicePub  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const string BobPriv   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const string BobPub    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const string Shared    = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    static byte[] H(string hex) => Convert.FromHexString(hex);
    static string X(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    [Fact]
    public void X25519Dh_reproduces_rfc7748_known_answer()
    {
        // If this fails after a Geralt bump, the library has switched to a KDF'd shared secret and EVERY
        // signature and seal is silently wrong. Do not "fix" it by updating the expected value.
        Assert.Equal(Shared, X(Primitives.X25519Dh(H(AlicePriv), H(BobPub))));
    }

    [Fact]
    public void X25519_public_derivation_matches_rfc7748()
    {
        Assert.Equal(AlicePub, X(Primitives.X25519PublicFromPrivate(H(AlicePriv))));
    }

    [Fact]
    public void X25519Dh_is_symmetric()
    {
        Assert.Equal(X(Primitives.X25519Dh(H(AlicePriv), H(BobPub))),
                     X(Primitives.X25519Dh(H(BobPriv), H(AlicePub))));
    }

    [Fact]
    public void X25519Dh_rejects_all_zero_peer_key_rather_than_yielding_a_predictable_secret()
    {
        // FLAG-8: raw scalarmult returns -1 on all-zero/small-subgroup output and that MUST be checked, or a
        // predictable key leaks. Geralt raises instead of returning, so the library satisfies the rule —
        // asserted here so a swap to a library that returns silently is caught.
        Assert.ThrowsAny<CryptographicException>(() => Primitives.X25519Dh(H(AlicePriv), new byte[32]));
    }

    [Fact]
    public void Ed25519_to_X25519_conversion_agrees_in_both_directions()
    {
        // FLAG-8c: pk_to_curve(edPk) and scalarmult_base(sk_to_curve(edSk)) MUST produce the identical X25519
        // public. Testing a single round-trip would not catch a one-directional bug.
        Span<byte> edPk = stackalloc byte[Primitives.Ed25519PublicKeySize];
        Span<byte> edSk = stackalloc byte[Primitives.Ed25519PrivateKeySize];
        Primitives.GenerateEd25519KeyPair(edPk, edSk);

        byte[] fromPub  = Primitives.Ed25519ToX25519Public(edPk);
        byte[] fromPriv = Primitives.X25519PublicFromPrivate(Primitives.Ed25519ToX25519Private(edSk));

        Assert.Equal(X(fromPub), X(fromPriv));
    }

    [Fact]
    public void Aead_uses_a_192_bit_nonce_and_binds_associated_data()
    {
        Assert.Equal(24, Primitives.AeadNonceSize);

        byte[] key = Primitives.RandomBytes(Primitives.AeadKeySize);
        byte[] nonce = Primitives.RandomBytes(Primitives.AeadNonceSize);
        byte[] pt = "sealed body"u8.ToArray();
        byte[] ad = "aead_ad_v1"u8.ToArray();

        byte[] ct = Primitives.AeadSeal(key, nonce, pt, ad);
        Assert.Equal(pt, Primitives.AeadOpen(key, nonce, ct, ad));

        // AD binding is what stops a relay transplanting a sealed body onto a different envelope.
        Assert.ThrowsAny<CryptographicException>(() => Primitives.AeadOpen(key, nonce, ct, "wrong_ad"u8.ToArray()));
    }

    [Fact]
    public void Hkdf_accepts_a_concatenated_ikm_and_treats_a_null_salt_as_32_zero_bytes()
    {
        // FLAG-8a: the KDF is unconditionally BCL HKDF-SHA256 over DH1‖…‖DH4‖transcript as ONE buffer. This is
        // exactly what NSec cannot do (it derives from a single opaque SharedSecret) and why it was dropped.
        byte[] ikm = Primitives.RandomBytes(128);
        byte[] info = "agentmail/v1/x3dh"u8.ToArray();

        byte[] withExplicitZeroSalt = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, new byte[32], info);
        Assert.Equal(32, Primitives.Hkdf(ikm, info).Length);
        Assert.Equal(Convert.ToHexString(withExplicitZeroSalt), Convert.ToHexString(Primitives.Hkdf(ikm, info)));
    }

    [Fact]
    public void KeyId_is_the_full_untruncated_digest_at_52_chars()
    {
        // FLAG-40: N is pinned to the FULL sha256 — 52 base32 chars, no truncation. A short N would reopen the
        // lookup-ambiguity and grinding surface this closes.
        byte[] pub = Primitives.RandomBytes(32);
        string id = Base32.KeyId(pub);
        Assert.Equal(52, id.Length);
        Assert.Equal(Base32.Encode(Primitives.Sha256(pub)), id);
    }
}
