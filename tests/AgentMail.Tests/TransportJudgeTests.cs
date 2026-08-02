using AgentMail;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// A relay can accept a message and then refuse to deliver it. The FLAG-32/38 CapabilityGate answers
/// <c>202 Accepted</c> with a <c>{"quarantined":...}</c> body when a plaintext envelope is addressed to an
/// e2e-capable recipient — the message lands in quarantine/, never the inbox. Judging on the status code
/// alone reports success for a message the recipient will never read.
///
/// Observed live: a direct POST to a peer relay returned
///   HTTP 202  {"quarantined":"bodycheck0001","reason":"e2e-peer-sent-plaintext"}
/// and every tool in the chain reported DELIVERED.
/// </summary>
public class TransportJudgeTests
{
    [Fact]
    public void Quarantined_202_is_a_FAILURE_not_a_delivery()
    {
        var (ok, detail) = Transport.Judge(
            202, "Accepted", "{\"quarantined\":\"bodycheck0001\",\"reason\":\"e2e-peer-sent-plaintext\"}");

        Assert.False(ok);
        Assert.Contains("QUARANTINED", detail);
        Assert.Contains("recipient will not see it", detail);
        // the original response is preserved so the caller can still diagnose
        Assert.Contains("e2e-peer-sent-plaintext", detail);
    }

    [Fact]
    public void Ordinary_202_delivery_is_still_success()
    {
        var (ok, detail) = Transport.Judge(
            202, "Accepted", "{\"delivered\":\"06FW26BKRK\",\"to\":\"wolf@wolf-prime\"}");

        Assert.True(ok);
        Assert.Contains("delivered", detail);
    }

    [Fact]
    public void Sealed_verified_delivery_is_success()
    {
        var (ok, _) = Transport.Judge(
            202, "Accepted", "{\"delivered\":\"06FW257WVK\",\"to\":\"wolf@wolf-prime\",\"sealed_verified\":true}");

        Assert.True(ok);
    }

    [Theory]
    [InlineData(200)]
    [InlineData(201)]
    [InlineData(204)]
    [InlineData(299)]
    public void Any_2xx_without_a_quarantine_marker_is_success(int status)
    {
        var (ok, _) = Transport.Judge(status, "OK", "{\"delivered\":\"x\"}");
        Assert.True(ok);
    }

    [Theory]
    [InlineData(401, "Unauthorized")]
    [InlineData(404, "Not Found")]
    [InlineData(400, "Bad Request")]
    [InlineData(500, "Internal Server Error")]
    public void Non_2xx_remains_a_failure(int status, string reason)
    {
        var (ok, detail) = Transport.Judge(status, reason, "");
        Assert.False(ok);
        Assert.Contains(status.ToString(), detail);
    }

    [Fact]
    public void Quarantine_marker_is_matched_case_insensitively()
    {
        var (ok, _) = Transport.Judge(202, "Accepted", "{\"QUARANTINED\":\"abc\"}");
        Assert.False(ok);
    }

    [Fact]
    public void The_word_quarantined_in_ordinary_prose_does_not_trip_the_gate()
    {
        // guards against over-matching: only the JSON field name counts, not the word in a subject or body echo
        var (ok, _) = Transport.Judge(
            202, "Accepted", "{\"delivered\":\"x\",\"subject\":\"why was my message quarantined?\"}");
        Assert.True(ok);
    }

    [Fact]
    public void A_non_2xx_carrying_a_quarantine_body_stays_a_failure()
    {
        var (ok, _) = Transport.Judge(409, "Conflict", "{\"quarantined\":\"abc\"}");
        Assert.False(ok);
    }
}
