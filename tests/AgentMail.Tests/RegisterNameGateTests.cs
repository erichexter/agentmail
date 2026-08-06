using AgentMail.Crypto;

namespace AgentMail.Tests;

/// <summary>
/// FLAG-41. `register` used to accept any name and store it verbatim, including names that
/// <see cref="PreImage.AssertLdh"/> — the gate <c>Seal.Create</c> applies to from.name/to.name —
/// rejects. The result was an agent that is unaddressable in BOTH directions, but only once
/// sealing arms: while a peer is unknown, sends go plaintext and never touch Identity, so the
/// break appears at the moment the security feature starts working rather than at registration.
///
/// Real incident (2026-08-06): an agent registered as "Elrond". Sending as it crashed the local
/// client with an unhandled NonConformingFieldException; sending TO it 500'd on the remote relay.
/// These tests pin the gate itself so registration can never again mint a name the transport refuses.
/// </summary>
public class RegisterNameGateTests
{
    [Theory]
    [InlineData("Elrond")]          // the real one — a single capital
    [InlineData("ELROND")]
    [InlineData("el rond")]         // space
    [InlineData("el_rond")]         // underscore is not LDH
    [InlineData("-elrond")]         // leading hyphen
    [InlineData("elrond-")]         // trailing hyphen
    [InlineData("elrond.two")]      // dot
    [InlineData("")]
    public void Names_the_sealed_path_refuses_are_refused_by_the_same_gate(string name)
    {
        Assert.Throws<NonConformingFieldException>(() => PreImage.AssertLdh(name, "agent name"));
    }

    [Theory]
    [InlineData("elrond")]
    [InlineData("harrell")]
    [InlineData("ranch-o-libre")]   // interior hyphens are fine
    [InlineData("agent7")]
    [InlineData("a")]
    public void Conforming_names_pass(string name)
    {
        Assert.Equal(name, PreImage.AssertLdh(name, "agent name"));
    }

    /// <summary>The CLI names the offending token back to the operator; digging it out of Message
    /// with a regex would be a maintenance trap, so the exception carries it.</summary>
    [Fact]
    public void The_exception_carries_the_offending_value_not_just_the_field()
    {
        var ex = Assert.Throws<NonConformingFieldException>(
            () => PreImage.AssertLdh("Elrond", "agent name"));

        Assert.Equal("agent name", ex.Field);
        Assert.Equal("Elrond", ex.Value);
    }

    /// <summary>register REJECTS rather than lowercasing. PreImage's contract is "reject, never
    /// normalize" (P2-K / FLAG-6) — silently registering 'Elrond' as 'elrond' hands the operator a
    /// name they neither chose nor saw, and the directory then disagrees with what they typed.</summary>
    [Fact]
    public void The_gate_does_not_normalize_it_rejects()
    {
        Assert.Throws<NonConformingFieldException>(() => PreImage.AssertLdh("Elrond", "addr.name"));
    }
}
