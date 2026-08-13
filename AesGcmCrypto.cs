//[4B magic 'SFRG'][16B Argon2 salt][12B GCM nonce][ciphertext][16B GCM tag]
using System.Security.Cryptography;
using System.Text;

namespace StegoForgeNet;

public static class AesGcmCrypto
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SFRG");
    private const int SaltLen = 16;
    private const int NonceLen = 12;
    private const int TagLen = 16;
    private const int HeaderLen = 4 + SaltLen + NonceLen;

    public static byte[] Encrypt(byte[] plaintext, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLen);
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);
        var key = Argon2Kdf.DeriveKey(password, salt);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLen];
        using var aes = new AesGcm(key, TagLen);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[HeaderLen + ciphertext.Length + TagLen];
        Buffer.BlockCopy(Magic, 0, result, 0, 4);
        Buffer.BlockCopy(salt, 0, result, 4, SaltLen);
        Buffer.BlockCopy(nonce, 0, result, 4 + SaltLen, NonceLen);
        Buffer.BlockCopy(ciphertext, 0, result, HeaderLen, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, HeaderLen + ciphertext.Length, TagLen);
        return result;
    }

    public static byte[] Decrypt(byte[] data, string password)
    {
        if (data.Length < HeaderLen + TagLen || !data.AsSpan(0, 4).SequenceEqual(Magic))
            throw new InvalidDataException("No encrypted payload found");

        var salt = data.AsSpan(4, SaltLen).ToArray();
        var nonce = data.AsSpan(4 + SaltLen, NonceLen).ToArray();
        var ciphertext = data.AsSpan(HeaderLen, data.Length - HeaderLen - TagLen).ToArray();
        var tag = data.AsSpan(data.Length - TagLen, TagLen).ToArray();

        var key = Argon2Kdf.DeriveKey(password, salt);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagLen);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (Exception)
        {
            throw new InvalidDataException("Decryption failed — wrong password or corrupted data");
        }
        return plaintext;
    }
}
