using System.Runtime.CompilerServices;

// The crypto seam is deliberately internal — Primitives/PreImage/Seal are not public API. The vector suite
// has to reach them to pin byte-for-byte behaviour, so grant it access rather than widening the surface.
[assembly: InternalsVisibleTo("AgentMail.Tests")]
