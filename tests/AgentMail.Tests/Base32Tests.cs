using AgentMail.Crypto;
using Xunit;

namespace AgentMail.Tests;

/// <summary>
/// Pins the base32 ALPHABET as a known-answer, not just the encoder's shape.
///
/// This exists because prose drifted from bytes: both the PRD App C addition and this file's own header
/// described Crockford as "RFC 4648 alphabet minus I, L, O, U". That is unconstructible — RFC 4648 is A-Z then
/// 2-7, so the subtraction yields 28 symbols with no digits, not Crockford's 32. The code was right and the
/// description was wrong, which is the dangerous direction: a reimplementer reads the description.
///
/// key_id and msg_id both pass through ascii() INSIDE the signed pre-image, so these characters are wire
/// contract. A KAT is the only thing that stops the alphabet being "fixed" toward RFC 4648 later.
/// </summary>
public class Base32Tests
{
    const string CrockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    // Independently derived (Python, no C# involved) before being pinned here.
    const string CountingBytes = "000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG";
    const string Rfc4648OfSameBytes = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ";

    static byte[] Counting32 => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    [Fact]
    public void Encodes_with_the_Crockford_alphabet_not_RFC4648()
    {
        string actual = Base32.Encode(Counting32);

        Assert.Equal(CountingBytes, actual);

        // The discriminating assertion. RFC 4648 over the identical input produces an entirely different
        // string, so this test fails loudly if anyone swaps the alphabet — which the old, wrong header comment
        // actively invited.
        Assert.NotEqual(Rfc4648OfSameBytes, actual);
    }

    [Fact]
    public void Alphabet_is_digits_first_and_omits_I_L_O_U()
    {
        // Every symbol the encoder can emit, in order: feed 5-bit values 0..31.
        var emitted = new string(Enumerable.Range(0, 32)
            .Select(i => Base32.Encode([(byte)(i << 3)])[0])
            .ToArray());

        Assert.Equal(CrockfordAlphabet, emitted);
        Assert.StartsWith("0123456789", emitted);          // digits first — RFC 4648 starts at 'A'
        foreach (char c in "ILOU") Assert.DoesNotContain(c, emitted);
        Assert.Equal(32, emitted.Length);                   // "RFC 4648 minus ILOU" would be 28
    }

    [Fact]
    public void Encoding_is_unpadded_and_uppercase_so_it_survives_ascii_ingress()
    {
        // The reason Crockford was chosen: the output must pass PreImage.AssertAscii unchanged and must not
        // collide with the addr() LDH rule. A '=' pad or a lowercase char would break the first.
        string s = Base32.Encode(Counting32);
        Assert.DoesNotContain("=", s);
        Assert.Equal(s.ToUpperInvariant(), s);
        Assert.Equal(s, PreImage.AssertAscii(s, "key_id"));
    }

    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000")]
    public void All_zero_key_encodes_to_all_zero_chars(string expected) =>
        Assert.Equal(expected, Base32.Encode(new byte[32]));

    [Fact]
    public void All_ones_key_encodes_to_the_high_symbol_with_the_tail_carrying_only_the_final_bit()
    {
        // 32 bytes = 256 bits = 51 full 5-bit groups + 1 leftover bit, left-aligned into the 52nd char.
        // The tail is 'G' (0b10000), not 'Z' — a real encoder property that a sloppy shift would get wrong.
        string s = Base32.Encode(Enumerable.Repeat((byte)0xFF, 32).ToArray());
        Assert.Equal(52, s.Length);
        Assert.Equal(new string('Z', 51) + "G", s);
    }

    [Fact]
    public void KeyId_is_52_chars_for_any_32_byte_key()
    {
        for (int i = 0; i < 16; i++)
            Assert.Equal(52, Base32.KeyId(Primitives.RandomBytes(32)).Length);
    }
}
