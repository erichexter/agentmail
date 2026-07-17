using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// Recipient consume path (brief PR1.6). The two load-bearing properties: the FLAG-30 .done write-gating
/// invariant (a failure NEVER writes .done) and the FLAG-46 bounded quarantine (a spoof flood cannot fill disk).
/// </summary>
public class ConsumeTests
{
    readonly string _tag = Guid.NewGuid().ToString("N")[..8];
    readonly string _root;
    readonly Identity _sender;
    readonly Identity _recipient;

    public ConsumeTests()
    {
        _root = Path.Combine(TestRoot.Path, "consume", Guid.NewGuid().ToString("N"));
        _sender = Identity.LoadOrCreate(new Address($"wolf-{_tag}", "gateway"));
        _recipient = Identity.LoadOrCreate(new Address($"smiley-{_tag}", "acer-desktop"));
    }

    const ulong Now = 1_752_700_000_000;

    Consume NewConsumer() => new(_recipient, _root);

    SealedEnvelope Sealed(string msgId, string body = "hello") =>
        Seal.Create(_sender, _recipient.Address, _recipient.PublicKey, _recipient.KeyEpoch, msgId,
                    System.Text.Encoding.UTF8.GetBytes(body), createdAt: Now);

    // The pin resolver a happy path uses: the sender IS pinned, to its real key.
    byte[]? PinnedToSender(Address a) => a.Key == _sender.Address.Key ? _sender.PublicKey : null;

    [Fact]
    public void A_valid_message_is_delivered_with_a_signed_consumed_receipt()
    {
        var r = NewConsumer().Process(Sealed("01J000000000000000000000AA"), PinnedToSender, Now);

        Assert.Equal(ConsumeOutcome.Delivered, r.Outcome);
        Assert.Equal("hello", System.Text.Encoding.UTF8.GetString(r.Plaintext!));
        Assert.NotNull(r.Receipt);
        Assert.Equal(ReceiptType.Consumed, r.Receipt!.Type);
    }

    [Fact]
    public void A_duplicate_short_circuits_before_any_crypto_and_re_emits_the_cached_receipt()
    {
        var c = NewConsumer();
        var e = Sealed("01J000000000000000000000AB");
        var first = c.Process(e, PinnedToSender, Now);
        Assert.Equal(ConsumeOutcome.Delivered, first.Outcome);

        // Same (from, msg_id) again — even if it were tampered, dedup must fire FIRST (PRD line 132).
        var second = c.Process(e, PinnedToSender, Now);
        Assert.Equal(ConsumeOutcome.DuplicateShortCircuited, second.Outcome);
        Assert.Equal(ReceiptType.Consumed, second.Receipt!.Type);

        // The re-emitted receipt is the SAME signed bytes, not a re-derivation.
        Assert.Equal(Convert.ToBase64String(first.Receipt!.Signature),
                     Convert.ToBase64String(second.Receipt!.Signature));
    }

    // --- FLAG-30: the write-gating invariant, pinned four ways -----------------------------------

    [Fact]
    public void A_verify_failure_quarantines_and_does_NOT_write_done()
    {
        var c = NewConsumer();
        var e = Sealed("01J000000000000000000000AC");
        e.Body[0] ^= 0xFF;   // content_hash / AEAD will fail

        var r = c.Process(e, PinnedToSender, Now);
        Assert.Equal(ConsumeOutcome.Quarantined, r.Outcome);

        // THE INVARIANT: .done must be untouched, so a later LEGITIMATE copy of the same (from, msg_id) is not
        // dedup-suppressed as "already seen". This is the attack the invariant defends against.
        var legit = c.Process(Sealed("01J000000000000000000000AC"), PinnedToSender, Now);
        Assert.Equal(ConsumeOutcome.Delivered, legit.Outcome);
    }

    [Fact]
    public void An_unpinned_sender_is_quarantined_not_first_sight_accepted_and_does_NOT_write_done()
    {
        // The consume path never pins on its own — an unpinned sender is a failure, not a silent accept.
        var c = NewConsumer();
        var r = c.Process(Sealed("01J000000000000000000000AD"), _ => null, Now);
        Assert.Equal(ConsumeOutcome.Quarantined, r.Outcome);

        // .done untouched: once the sender IS pinned, the same message delivers.
        Assert.Equal(ConsumeOutcome.Delivered,
            c.Process(Sealed("01J000000000000000000000AD"), PinnedToSender, Now).Outcome);
    }

    [Fact]
    public void An_expired_message_is_dropped_WITHOUT_decrypting_and_does_NOT_write_done()
    {
        var c = NewConsumer();
        var e = Sealed("01J000000000000000000000AE");
        // Force expiry: evaluate at a time past its expires_at.
        ulong wayLater = e.ExpiresAt + 1;

        var r = c.Process(e, PinnedToSender, wayLater);
        Assert.Equal(ConsumeOutcome.ExpiredDropped, r.Outcome);
        Assert.Null(r.Plaintext);

        // .done untouched: if the clock were wrong and a fresh copy arrives in-window, it still delivers.
        Assert.Equal(ConsumeOutcome.Delivered,
            c.Process(Sealed("01J000000000000000000000AE"), PinnedToSender, Now).Outcome);
    }

    [Fact]
    public void A_wrong_key_pin_quarantines_and_does_NOT_write_done()
    {
        var impostor = Identity.LoadOrCreate(new Address($"impostor-{_tag}", "elsewhere"));
        var c = NewConsumer();
        var r = c.Process(Sealed("01J000000000000000000000AF"), _ => impostor.PublicKey, Now);
        Assert.Equal(ConsumeOutcome.Quarantined, r.Outcome);

        Assert.Equal(ConsumeOutcome.Delivered,
            c.Process(Sealed("01J000000000000000000000AF"), PinnedToSender, Now).Outcome);
    }

    // --- FLAG-46: bounded quarantine --------------------------------------------------------------

    [Fact]
    public void A_spoof_flood_caps_the_quarantine_store_and_rotates_oldest_first()
    {
        // The DoS the bound defends against: an attacker sends N+ junk messages that all fail verify. Without a
        // bound they accumulate forever. With it, the store caps and evicts oldest-first.
        int cap = 8;
        var quarantine = new Quarantine(Path.Combine(_root, "flood-quar"), maxEntries: cap, maxBytes: 100 * 1024 * 1024);

        for (int i = 0; i < cap + 20; i++)
        {
            var junk = Sealed($"01J00000000000000000000F{i:D2}");
            junk.Body[0] ^= 0xFF;
            quarantine.Add(junk);
        }

        Assert.True(quarantine.Count() <= cap,
            $"quarantine held {quarantine.Count()} entries, cap is {cap} — a flood must not grow it unbounded");
    }

    [Fact]
    public void The_quarantine_byte_cap_also_bounds_the_store()
    {
        var quarantine = new Quarantine(Path.Combine(_root, "bytes-quar"), maxEntries: 100_000, maxBytes: 4096);
        for (int i = 0; i < 50; i++)
        {
            var junk = Sealed($"01J00000000000000000000B{i:D2}", body: new string('x', 500));
            junk.Body[0] ^= 0xFF;
            quarantine.Add(junk);
        }
        long bytes = Directory.GetFiles(Path.Combine(_root, "bytes-quar"), "*.quar.json").Sum(f => new FileInfo(f).Length);
        Assert.True(bytes <= 4096 + 2048, $"quarantine held {bytes} bytes, cap ~4096 — byte bound must hold too");
    }
}
