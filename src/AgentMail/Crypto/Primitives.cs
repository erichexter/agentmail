using System.Security.Cryptography;
using Geralt;

namespace AgentMail.Crypto;

/// <summary>
/// The only file in the codebase that touches curve, AEAD or KDF math. Everything else calls in here.
///
/// Library binding is the outcome of the FLAG-8 spike (2026-07-16, 13/13, gate PASS): Geralt 4.3.0 for
/// X25519 / XChaCha20-Poly1305 / Ed25519 / Ed25519↔X25519, and the BCL for HKDF-SHA256. NSec is not used
/// (its <c>Agree</c> returns an opaque, non-exportable SharedSecret, so it cannot produce the raw DH bytes
/// X3DH concatenates). There is no P/Invoke on any path: Geralt ships a per-RID libsodium 1.0.22 native and
/// loads it from the app directory, verified on a bare dotnet/runtime:10.0 image with no system libsodium.
///
/// Versions are pinned in the csproj. Re-run tests/vectors on any bump.
/// </summary>
static class Primitives
{
    public const int X25519PublicKeySize = 32;
    public const int X25519PrivateKeySize = 32;
    public const int SharedSecretSize = 32;
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519PrivateKeySize = 64;   // seed(32) || pubkey(32)
    public const int Ed25519SignatureSize = 64;
    public const int AeadKeySize = 32;
    public const int AeadNonceSize = 24;           // XChaCha20 — 192-bit
    public const int AeadTagSize = 16;
    public const int Sha256Size = 32;

    /// <summary>RFC 5869 null salt: HKDF substitutes HashLen zero bytes. Vectors pin the explicit form (FLAG-8a).</summary>
    static readonly byte[] HkdfNullSalt = new byte[32];

    // --- Randomness -------------------------------------------------------------------------------

    /// <summary>CSPRNG fill. Nonces, ephemeral keys and one-time prekeys come from here — never Guid/System.Random.</summary>
    public static void FillRandom(Span<byte> buffer) => RandomNumberGenerator.Fill(buffer);

    public static byte[] RandomBytes(int count)
    {
        var b = new byte[count];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    // --- Hash -------------------------------------------------------------------------------------

    public static byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);

    // --- X25519 -----------------------------------------------------------------------------------

    public static void GenerateX25519KeyPair(Span<byte> publicKey, Span<byte> privateKey) =>
        X25519.GenerateKeyPair(publicKey, privateKey);

    public static byte[] X25519PublicFromPrivate(ReadOnlySpan<byte> privateKey)
    {
        var pk = new byte[X25519PublicKeySize];
        X25519.ComputePublicKey(pk, privateKey);
        return pk;
    }

    /// <summary>
    /// Raw X25519 scalar multiplication — the un-KDF'd 32 bytes X3DH concatenates as DH1‖…‖DH4.
    ///
    /// This is <c>ComputeSharedSecret</c>, NOT <c>DeriveSenderSharedKey</c>/<c>DeriveRecipientSharedKey</c>:
    /// those are Geralt's misuse-resistant helpers and return a BLAKE2b-KDF'd value, which would silently
    /// produce a wrong SK. The spike pinned this distinction against RFC 7748 §6.1 (a KDF'd output cannot
    /// reproduce the known-answer vector); <c>PrimitivesTests</c> keeps it pinned.
    ///
    /// Contributory behaviour: an all-zero / small-subgroup result throws rather than yielding a predictable
    /// key. Geralt raises CryptographicException, so the libsodium <c>!= 0 ⇒ throw</c> rule is satisfied by
    /// the library — asserted in tests so a library swap cannot silently regress it.
    /// </summary>
    public static byte[] X25519Dh(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
    {
        var shared = new byte[SharedSecretSize];
        X25519.ComputeSharedSecret(shared, privateKey, peerPublicKey);   // throws on all-zero/small-subgroup
        return shared;
    }

    // --- Ed25519 ----------------------------------------------------------------------------------

    public static void GenerateEd25519KeyPair(Span<byte> publicKey, Span<byte> privateKey) =>
        Ed25519.GenerateKeyPair(publicKey, privateKey);

    public static byte[] Ed25519PublicFromPrivate(ReadOnlySpan<byte> privateKey)
    {
        var pk = new byte[Ed25519PublicKeySize];
        Ed25519.GetPublicKey(pk, privateKey);
        return pk;
    }

    public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        var sig = new byte[Ed25519SignatureSize];
        Ed25519.Sign(sig, message, privateKey);
        return sig;
    }

    public static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != Ed25519SignatureSize || publicKey.Length != Ed25519PublicKeySize) return false;
        return Ed25519.Verify(signature, message, publicKey);
    }

    // --- Ed25519 → X25519 -------------------------------------------------------------------------
    // FLAG-2 was resolved by the spike: Geralt exposes both directions in managed API and they agree, so
    // there is no libsodium conversion shim and the 64-byte-sk reconstruction gotcha does not arise
    // (Geralt's Ed25519 private key is already the 64-byte seed‖pubkey form).

    public static byte[] Ed25519ToX25519Public(ReadOnlySpan<byte> ed25519PublicKey)
    {
        var x = new byte[X25519PublicKeySize];
        Ed25519.ComputeX25519PublicKey(x, ed25519PublicKey);
        return x;
    }

    public static byte[] Ed25519ToX25519Private(ReadOnlySpan<byte> ed25519PrivateKey)
    {
        var x = new byte[X25519PrivateKeySize];
        Ed25519.ComputeX25519PrivateKey(x, ed25519PrivateKey);
        return x;
    }

    // --- KDF --------------------------------------------------------------------------------------

    /// <summary>
    /// HKDF-SHA256 over an arbitrary concatenated IKM (DH1‖…‖DH4‖transcript), salt = 32×0x00, info = a DS tag.
    ///
    /// Unconditionally the BCL (FLAG-8a). NOT libsodium's <c>crypto_kdf</c> — that is BLAKE2b, the wrong
    /// primitive, and NOT NSec's HkdfSha256 — that derives from a single opaque SharedSecret and cannot take
    /// a concatenated buffer.
    /// </summary>
    public static byte[] Hkdf(byte[] ikm, byte[] info, int outputLength = 32) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, outputLength, HkdfNullSalt, info);

    // --- AEAD -------------------------------------------------------------------------------------

    /// <summary>
    /// XChaCha20-Poly1305 seal. Returns ct‖tag.
    ///
    /// FLAG-47: (SK, nonce) are single-use. They live for one call and the caller zeroes them immediately
    /// after — see <see cref="Zero"/>. No code path may retain them for a subsequent encryption: re-encrypting
    /// different plaintext under the same nonce is catastrophic (keystream reuse + Poly1305 key exposure).
    /// The only thing cached for a transport retry is the finished ct‖tag blob, keyed (msg_id, to).
    /// </summary>
    public static byte[] AeadSeal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
                                  ReadOnlySpan<byte> plaintext, byte[] associatedData)
    {
        var ct = new byte[plaintext.Length + AeadTagSize];
        XChaCha20Poly1305.Encrypt(ct, plaintext, nonce, key, associatedData);
        return ct;
    }

    /// <summary>XChaCha20-Poly1305 open. Throws CryptographicException on tag mismatch (wrong key/nonce/AD/ciphertext).</summary>
    public static byte[] AeadOpen(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
                                  ReadOnlySpan<byte> ciphertextAndTag, byte[] associatedData)
    {
        if (ciphertextAndTag.Length < AeadTagSize) throw new CryptographicException("ciphertext shorter than tag");
        var pt = new byte[ciphertextAndTag.Length - AeadTagSize];
        XChaCha20Poly1305.Decrypt(pt, ciphertextAndTag, nonce, key, associatedData);
        return pt;
    }

    // --- Hygiene ----------------------------------------------------------------------------------

    /// <summary>Zero key material. Call on SK/nonce immediately after seal/open (FLAG-47).</summary>
    public static void Zero(Span<byte> secret) => CryptographicOperations.ZeroMemory(secret);

    /// <summary>Constant-time compare, for tags/hashes/fingerprints.</summary>
    public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        CryptographicOperations.FixedTimeEquals(a, b);
}
