using System.Text.Json;
using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// FLAG-42 (unknown-field tolerance) + FLAG-9 (capability + storage). The cross-version parse test is the one
/// that matters: a strict deserializer would split the gossip directory the moment a newer node adds a field.
/// </summary>
public class StorageTests
{
    [Fact]
    public void An_AgentRecord_with_UNKNOWN_future_fields_still_parses_and_keeps_the_known_ones()
    {
        // The FLAG-42 scenario: a newer node gossips a record with fields this build has never heard of. A
        // strict parser (UnmappedMemberHandling.Disallow) would THROW here and drop the record -> directory
        // split. It must skip the unknowns and keep the known fields.
        string fromNewerNode = """
        {
          "agent": "wolf",
          "host": "gateway",
          "endpoint": "http://gateway:8787",
          "status": "online",
          "version": 7,
          "last_seen": "2026-07-17T12:00:00Z",
          "record_epoch": 3,
          "key_epoch": 2,
          "spk_pub": "AAAA",
          "opk": [{"opk_id": 1, "opk_pub": "BBBB"}],
          "some_field_from_pr9_that_does_not_exist_yet": {"nested": true},
          "another_unknown": [1, 2, 3]
        }
        """;

        var rec = JsonSerializer.Deserialize<AgentRecord>(fromNewerNode, AgentMail.Paths.Json);

        Assert.NotNull(rec);
        Assert.Equal("wolf", rec!.Agent);
        Assert.Equal("gateway", rec.Host);
        Assert.Equal(7, rec.Version);
        Assert.Equal("online", rec.Status);
    }

    [Fact]
    public void A_SealedEnvelope_with_unknown_fields_still_parses()
    {
        // Same rule on the envelope path — a PR1 node receiving a PR2 envelope (spk/opk fields it lacks) must
        // parse it, not reject it.
        string withPr2Fields = """
        {
          "msg_id": "01J000000000000000000000AB",
          "protocol_version": 1,
          "from": {"name": "wolf", "host": "gateway"},
          "to": {"name": "smiley", "host": "acer-desktop"},
          "content_type": "text/markdown",
          "size": 48,
          "enc": {"mode": 1, "sender_key_id": "x", "spk_epoch": 4, "opk_id": 9, "some_pr2_field": "z"},
          "future_top_level_field": {"a": 1}
        }
        """;

        var env = JsonSerializer.Deserialize<SealedEnvelope>(withPr2Fields, AgentMail.Paths.Json);
        Assert.NotNull(env);
        Assert.Equal("01J000000000000000000000AB", env!.MsgId);
        Assert.Equal(4u, env.Enc.SpkEpoch);
        Assert.Equal(9u, env.Enc.OpkId);
    }

    [Fact]
    public void The_JSON_options_explicitly_skip_unknown_members_not_disallow()
    {
        // Pins the config itself, so flipping it to Disallow is a failing-test edit rather than a silent
        // regression that only shows up as a mysterious directory split in production.
        Assert.Equal(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Skip,
                     AgentMail.Paths.Json.UnmappedMemberHandling);
    }

    [Fact]
    public void Caps_advertises_msg_json_so_the_watcher_can_probe_for_it()
    {
        Assert.Contains(AgentMail.Capabilities.MsgJson, AgentMail.Capabilities.All);
        Assert.Equal("msg-json", AgentMail.Capabilities.MsgJson);
    }

    [Fact]
    public void An_enc_envelope_serializes_to_msg_json_and_legacy_to_msg_md()
    {
        // FLAG-5: enc envelopes go to *.msg.json, legacy plaintext stays *.msg.md. The two names are kept
        // distinct on disk so a legacy watcher never sees a json file it cannot parse (FLAG-9).
        var enc = new SealedEnvelope { MsgId = "01J000000000000000000000AB" };
        Assert.EndsWith(".msg.json", enc.FileName);

        var legacy = new Envelope { Id = "abc123" };
        Assert.EndsWith(".msg.md", legacy.FileName);
    }
}
