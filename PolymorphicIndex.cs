// PolymorphicIndex.cs — key-seeded pixel traversal order, compatible with
// core/crypto/polymorphic.py. Only row_reversed and shuffle_seed are
// consumed by the LSB encoder (channel_order/bit_position are derived in
// the Python module but never read by lsb.py — kept out here on purpose).
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace StegoForgeNet;

public static class PolymorphicIndex
{
    public static (bool RowReversed, ulong ShuffleSeed) DeriveParams(string key)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        bool rowReversed = digest[4] % 2 == 0;
        ulong shuffleSeed = BinaryPrimitives.ReadUInt64BigEndian(digest.AsSpan(5, 8));
        return (rowReversed, shuffleSeed);
    }

    // Deterministic LCG-seeded Fisher-Yates shuffle — must match
    // fisher_yates_indices() in polymorphic.py bit-for-bit.
    public static int[] FisherYatesIndices(int n, ulong seed)
    {
        var indices = new int[n];
        for (int i = 0; i < n; i++) indices[i] = i;

        ulong state = seed;
        for (int i = n - 1; i > 0; i--)
        {
            state = state * 6364136223846793005UL + 1442695040888963407UL; // wraps mod 2^64
            int j = (int)(state % (ulong)(i + 1));
            (indices[i], indices[j]) = (indices[j], indices[i]);
        }
        return indices;
    }

    public static int[] BuildIndices(int n, string? key)
    {
        if (string.IsNullOrEmpty(key))
        {
            var seq = new int[n];
            for (int i = 0; i < n; i++) seq[i] = i;
            return seq;
        }

        var (rowReversed, shuffleSeed) = DeriveParams(key);
        if (rowReversed)
        {
            var reversed = new int[n];
            for (int i = 0; i < n; i++) reversed[i] = n - 1 - i;
            return reversed;
        }
        return FisherYatesIndices(n, shuffleSeed);
    }
}
