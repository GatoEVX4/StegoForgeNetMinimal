// Argon2Kdf.cs — Argon2id key derivation, parameter-compatible with
// core/crypto/kdf.py (argon2-cffi: time_cost=2, memory_cost=65536 KiB,
// parallelism=2, hash_len=32, type=Argon2id).
using Konscious.Security.Cryptography;

namespace StegoForgeNet;

public static class Argon2Kdf
{
    public static byte[] DeriveKey(string password, byte[] salt, int keyLen = 32)
    {
        if (salt.Length != 16)
            throw new ArgumentException($"Salt must be 16 bytes, got {salt.Length}");

        using var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 2,
            Iterations = 2,
            MemorySize = 65536, // KiB
        };
        return argon2.GetBytes(keyLen);
    }
}
