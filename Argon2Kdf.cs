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
