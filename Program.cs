namespace StegoForgeNet;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        try
        {
            switch (args[0])
            {
                case "encode":
                    return CmdEncode(args);
                case "decode":
                    return CmdDecode(args);
                default:
                    PrintUsage();
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    static int CmdEncode(string[] args)
    {
        if (args.Length < 5)
        {
            Console.Error.WriteLine("Usage: encode <carrier.png> <payload.bin> <key> <output.png> [depth=1]");
            return 1;
        }

        string carrierPath = args[1];
        string payloadPath = args[2];
        string key = args[3];
        string outputPath = args[4];
        int depth = args.Length > 5 ? int.Parse(args[5]) : 1;

        byte[] carrierBytes = File.ReadAllBytes(carrierPath);
        byte[] payloadBytes = File.ReadAllBytes(payloadPath);

        byte[] embedBytes = string.IsNullOrEmpty(key) ? payloadBytes : AesGcmCrypto.Encrypt(payloadBytes, key);

        int cap = LsbCodec.Capacity(carrierBytes, depth);
        if (embedBytes.Length > cap)
        {
            Console.Error.WriteLine($"Encrypted payload too large: {embedBytes.Length} bytes, capacity at depth={depth}: {cap} bytes.");
            return 1;
        }

        byte[] stegoBytes = LsbCodec.Encode(carrierBytes, embedBytes, depth, key);
        File.WriteAllBytes(outputPath, stegoBytes);

        Console.WriteLine($"OK: {payloadBytes.Length} bytes payload -> {embedBytes.Length} bytes embedded -> {outputPath}");
        return 0;
    }

    static int CmdDecode(string[] args)
    {
        if (args.Length < 4)
        {
            Console.Error.WriteLine("Usage: decode <stego.png> <key> <output.bin> [depth=1]");
            return 1;
        }

        string stegoPath = args[1];
        string key = args[2];
        string outputPath = args[3];
        int depth = args.Length > 4 ? int.Parse(args[4]) : 1;

        byte[] stegoBytes = File.ReadAllBytes(stegoPath);
        byte[] rawBytes = LsbCodec.Decode(stegoBytes, depth, key);
        byte[] payloadBytes = string.IsNullOrEmpty(key) ? rawBytes : AesGcmCrypto.Decrypt(rawBytes, key);

        File.WriteAllBytes(outputPath, payloadBytes);
        Console.WriteLine($"OK: {payloadBytes.Length} bytes extracted -> {outputPath}");
        return 0;
    }

    static void PrintUsage()
    {
        Console.WriteLine("minimal LSB image steganography");
        Console.WriteLine();
        Console.WriteLine("  encode <carrier.png> <payload.bin> <key> <output.png> [depth=1]");
        Console.WriteLine("  decode <stego.png> <key> <output.bin> [depth=1]");
    }
}
