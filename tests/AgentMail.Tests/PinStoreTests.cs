using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// TOFU pin store — the entire trust root in PR1/PR2 (no CA until PR3). These tests pin the security contract:
/// once a key is pinned it never silently changes, and epoch state fails closed.
/// </summary>
public class PinStoreTests
{
    readonly string _tag = Guid.NewGuid().ToString("N")[..8];
    // Stable per test instance — an expression-bodied `=>` here would mint a fresh GUID on every read, so the
    // store and the test would look at different directories. (xUnit news up one instance per test, so this is
    // already per-test-unique.)
    readonly string Root = Path.Combine(TestRoot.Path, "pki", Guid.NewGuid().ToString("N"));

    Identity NewId(string name) => Identity.LoadOrCreate(new Address($"{name}-{_tag}", "peer-host"));

    [Fact]
    public void First_sight_pins_the_record()
    {
        var store = new PinStore(Root);
        var record = AgentCertLite.Create(NewId("wolf"));

        Assert.Equal(PinResult.PinnedFirstSight, store.Offer(record));
        Assert.NotNull(store.Get(record.Addr));
        Assert.Equal(record.KeyId, store.Get(record.Addr)!.KeyId);
    }

    [Fact]
    public void A_record_whose_self_signature_is_broken_is_rejected_before_any_pin()
    {
        var store = new PinStore(Root);
        var record = AgentCertLite.Create(NewId("wolf"));
        record.AgentSig[0] ^= 0xFF;

        Assert.Equal(PinResult.RejectedBadSignature, store.Offer(record));
        Assert.Null(store.Get(record.Addr));   // nothing pinned from an unverifiable record
    }

    [Fact]
    public void A_DIFFERENT_ident_pub_for_a_pinned_peer_is_REJECTED_regardless_of_epoch()
    {
        // FLAG-8b — the core defense. With no CA, a self-signed record presenting a NEW key and a higher epoch
        // is exactly the key-substitution attack. It must be refused, not auto-accepted on the higher epoch.
        var store = new PinStore(Root);
        var addr = new Address($"victim-{_tag}", "peer-host");

        // Pin the legitimate key.
        Directory.CreateDirectory(Identity.KeyDir(addr));
        var legit = Identity.LoadOrCreate(addr);
        Assert.Equal(PinResult.PinnedFirstSight, store.Offer(AgentCertLite.Create(legit, recordEpoch: 1)));

        // Attacker forges a record for the same name@host with THEIR OWN key and a much higher epoch.
        var attackerKey = Identity.LoadOrCreate(new Address($"attacker-{_tag}", "elsewhere"));
        var forged = new AgentCertLite
        {
            Addr = addr,                          // claims the victim's name@host
            IdentPub = attackerKey.PublicKey,     // but the attacker's key
            KeyEpoch = 99,
            RecordEpoch = 9999,                    // and a sky-high epoch to try to win monotonicity
        };
        forged.AgentSig = attackerKey.Sign(PreImage.DsAgentCert, PreImage.SignInputAgentCertLite(forged));

        Assert.True(forged.VerifySelfSignature());               // it IS a valid self-signature...
        Assert.Equal(PinResult.RejectedKeyMismatch, store.Offer(forged));   // ...and it is STILL rejected
        Assert.Equal(legit.KeyId, store.Get(addr)!.KeyId);       // the original pin stands
    }

    [Fact]
    public void Same_key_with_a_higher_record_epoch_updates()
    {
        var store = new PinStore(Root);
        var addr = new Address($"peer-{_tag}", "peer-host");
        Directory.CreateDirectory(Identity.KeyDir(addr));
        var id = Identity.LoadOrCreate(addr);

        Assert.Equal(PinResult.PinnedFirstSight, store.Offer(AgentCertLite.Create(id, recordEpoch: 1)));
        Assert.Equal(PinResult.Updated, store.Offer(AgentCertLite.Create(id, recordEpoch: 5)));
        Assert.Equal(5ul, store.Get(addr)!.RecordEpoch);
    }

    [Fact]
    public void Same_key_with_a_lower_or_equal_record_epoch_is_a_rollback_and_is_ignored()
    {
        var store = new PinStore(Root);
        var addr = new Address($"peer-{_tag}", "peer-host");
        Directory.CreateDirectory(Identity.KeyDir(addr));
        var id = Identity.LoadOrCreate(addr);

        store.Offer(AgentCertLite.Create(id, recordEpoch: 5));
        Assert.Equal(PinResult.Unchanged, store.Offer(AgentCertLite.Create(id, recordEpoch: 5)));   // equal
        Assert.Equal(PinResult.Unchanged, store.Offer(AgentCertLite.Create(id, recordEpoch: 3)));   // lower
        Assert.Equal(5ul, store.Get(addr)!.RecordEpoch);
    }

    [Fact]
    public void A_corrupt_epoch_map_is_re_derived_from_the_pin_rather_than_accepting_anything()
    {
        // FLAG-43 — fail closed, but re-derive from the pinned record first: it is itself authority for its
        // own last-known epoch, so a lost epoch file need not force an operator re-pin if the pin survives.
        var store = new PinStore(Root);
        var addr = new Address($"peer-{_tag}", "peer-host");
        Directory.CreateDirectory(Identity.KeyDir(addr));
        var id = Identity.LoadOrCreate(addr);
        store.Offer(AgentCertLite.Create(id, recordEpoch: 5));

        // Corrupt the epoch high-water file, leaving the pin intact. The first Offer already created state/.
        string epochPath = Path.Combine(Root, "state", "epochs.json");
        Assert.True(File.Exists(epochPath), "first Offer should have written the epoch high-water");
        File.WriteAllText(epochPath, "{ this is not json");

        // A rollback to epoch 3 must still be refused — the pin's own record_epoch (5) is re-derived as the floor.
        Assert.Equal(PinResult.Unchanged, store.Offer(AgentCertLite.Create(id, recordEpoch: 3)));
        // And a genuine advance still works.
        Assert.Equal(PinResult.Updated, store.Offer(AgentCertLite.Create(id, recordEpoch: 9)));
    }

    [Fact]
    public void The_key_id_binds_to_the_ident_pub()
    {
        var store = new PinStore(Root);
        var record = AgentCertLite.Create(NewId("wolf"));
        store.Offer(record);
        Assert.Equal(Base32.KeyId(record.IdentPub), store.Get(record.Addr)!.KeyId);
    }
}
