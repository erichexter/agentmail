using System.Text.Json;

namespace AgentMail.Crypto;

/// <summary>
/// An agent's long-term Ed25519 identity keypair, scoped to name@host and minted at register.
///
/// Storage (§5): ~/.claude/agentmail/keys/&lt;name&gt;@&lt;host&gt;/ident.key, dir 0700, file 0600, asserted at startup.
///
/// HONEST DISCLOSURE — the private key is stored UNENCRYPTED on disk in PR1/PR2 (FLAG-34/B-NEW-4). A disk
/// thief holding it plus the public envelope fields recomputes SK for every message currently in the inbox.
/// So forward secrecy covers CONSUMED/RETIRED keys only, against an adversary who does not already hold these
/// bytes — never claim "FS from message 1" unqualified. POSIX perms also buy nothing against a same-uid
/// sibling process: siblings share the uid. Extending keyring/TPM wrapping to ident.key is the only thing
/// that would push disk-theft resistance to in-flight messages (a planned hardening, disclosed not omitted).
/// </summary>
sealed class Identity
{
    public Address Address { get; }
    public byte[] PublicKey { get; }
    public uint KeyEpoch { get; }

    readonly byte[] _privateKey;

    /// <summary>base32(sha256(ident_pub)), N=52 — the stable long-term pseudonymous linker (FLAG-40).</summary>
    public string KeyId { get; }

    Identity(Address address, byte[] publicKey, byte[] privateKey, uint keyEpoch)
    {
        Address = address;
        PublicKey = publicKey;
        _privateKey = privateKey;
        KeyEpoch = keyEpoch;
        KeyId = Base32.KeyId(publicKey);
    }

    public static string KeyDir(Address a) => Path.Combine(Paths.Root, "keys", $"{a.Name}@{a.Host}");
    static string IdentPath(Address a) => Path.Combine(KeyDir(a), "ident.key");

    /// <summary>Load the identity for name@host, minting one on first use. Idempotent.</summary>
    public static Identity LoadOrCreate(Address address)
    {
        // Reject non-conforming identity text here rather than normalizing it (P2-K). Lowercasing is a MINT
        // concern: a machine-name fallback like DESKTOP-EXAMPLE must be lowercased before it reaches this
        // point, never silently folded afterwards.
        PreImage.AssertLdh(address.Name, "name");
        PreImage.AssertLdh(address.Host, "host");

        string path = IdentPath(address);
        if (File.Exists(path))
        {
            var stored = JsonSerializer.Deserialize<StoredKey>(File.ReadAllText(path), Paths.Json)
                         ?? throw new InvalidOperationException($"unreadable identity key: {path}");
            AssertPrivatePerms(path);
            return new Identity(address, Convert.FromBase64String(stored.PublicKey),
                                Convert.FromBase64String(stored.PrivateKey), stored.KeyEpoch);
        }

        Span<byte> pub = stackalloc byte[Primitives.Ed25519PublicKeySize];
        Span<byte> priv = stackalloc byte[Primitives.Ed25519PrivateKeySize];
        Primitives.GenerateEd25519KeyPair(pub, priv);

        var id = new Identity(address, pub.ToArray(), priv.ToArray(), keyEpoch: 1);
        id.Save();
        return id;
    }

    void Save()
    {
        string dir = KeyDir(Address);
        Directory.CreateDirectory(dir);
        SetUnixMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);   // 0700

        string path = IdentPath(Address);
        var stored = new StoredKey(Convert.ToBase64String(PublicKey), Convert.ToBase64String(_privateKey), KeyEpoch);
        Io.WriteAtomic(path, JsonSerializer.Serialize(stored, Paths.Json));
        SetUnixMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);                             // 0600
    }

    /// <summary>Ed25519 over DS_AUTH ‖ sign_input_v1 — the envelope signature.</summary>
    public byte[] SignEnvelope(SealedEnvelope e) => Sign(PreImage.DsAuth, PreImage.SignInputV1(e));

    /// <summary>Ed25519 over a DS-tagged pre-image. The tag is prepended, never mixed into the TLV.</summary>
    public byte[] Sign(string domainSeparationTag, ReadOnlySpan<byte> preImage)
    {
        var tag = System.Text.Encoding.ASCII.GetBytes(domainSeparationTag);
        var msg = new byte[tag.Length + preImage.Length];
        tag.CopyTo(msg, 0);
        preImage.CopyTo(msg.AsSpan(tag.Length));
        return Primitives.Sign(msg, _privateKey);
    }

    public static bool VerifyDetached(string domainSeparationTag, ReadOnlySpan<byte> preImage,
                                      ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        var tag = System.Text.Encoding.ASCII.GetBytes(domainSeparationTag);
        var msg = new byte[tag.Length + preImage.Length];
        tag.CopyTo(msg, 0);
        preImage.CopyTo(msg.AsSpan(tag.Length));
        return Primitives.Verify(signature, msg, publicKey);
    }

    /// <summary>The X25519 form of this identity, for the X3DH DHs. Both directions were spike-verified to agree.</summary>
    public byte[] X25519Private() => Primitives.Ed25519ToX25519Private(_privateKey);
    public byte[] X25519Public() => Primitives.Ed25519ToX25519Public(PublicKey);

    static void SetUnixMode(string path, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows()) return;
        try { File.SetUnixFileMode(path, mode); } catch (Exception) { /* best-effort; startup assert is the real gate */ }
    }

    /// <summary>Refuse to run on a world/group-readable private key. Alerts rather than silently continuing.</summary>
    static void AssertPrivatePerms(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        var mode = File.GetUnixFileMode(path);
        const UnixFileMode leaked = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                                  | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((mode & leaked) != 0)
            throw new InvalidOperationException(
                $"identity key {path} is group/world-accessible ({mode}); refusing to load. chmod 600 it.");
    }

    sealed record StoredKey(string PublicKey, string PrivateKey, uint KeyEpoch);
}
