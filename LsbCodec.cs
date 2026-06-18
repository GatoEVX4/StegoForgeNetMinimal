// LsbCodec.cs — LSB image steganography, wire-compatible with
// core/image/lsb.py for true-color RGB/RGBA PNG carriers.
//
// Wire format embedded in pixels:
//   [4 bytes big-endian uint32: payload length][payload bytes]
//
// Scope (kept intentionally minimal):
//   - PNG only, RGB (3ch) or RGBA (4ch) true-color. Grayscale, palette and
//     other formats (BMP/TIFF/WEBP) that the Python tool also supports are
//     NOT replicated here — out of scope for a minimal port.
using System.Buffers.Binary;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.PixelFormats;

namespace StegoForgeNet;

public static class LsbCodec
{
    private const int HeaderSize = 4;

    public static int Capacity(byte[] carrierBytes, int depth = 1)
    {
        var (_, _, _, flat) = LoadChannels(carrierBytes);
        long totalBits = (long)flat.Length * depth;
        return (int)(totalBits / 8) - HeaderSize;
    }

    public static byte[] Encode(byte[] carrierBytes, byte[] payloadBytes, int depth = 1, string? key = null)
    {
        var (channels, width, height, flat) = LoadChannels(carrierBytes);

        int cap = (int)(((long)flat.Length * depth) / 8) - HeaderSize;
        if (payloadBytes.Length > cap)
            throw new ArgumentException($"Payload too large: {payloadBytes.Length} bytes, capacity: {cap} bytes");

        var data = new byte[HeaderSize + payloadBytes.Length];
        BinaryPrimitives.WriteUInt32BigEndian(data, (uint)payloadBytes.Length);
        Buffer.BlockCopy(payloadBytes, 0, data, HeaderSize, payloadBytes.Length);
        var bits = BytesToBits(data);

        var indices = PolymorphicIndex.BuildIndices(flat.Length, key);

        int mask = (0xFF << depth) & 0xFF;
        int bitIdx = 0;
        foreach (var idx in indices)
        {
            if (bitIdx >= bits.Length) break;
            int count = Math.Min(depth, bits.Length - bitIdx);
            int chunkVal = 0;
            for (int k = 0; k < count; k++) chunkVal = (chunkVal << 1) | bits[bitIdx + k];
            flat[idx] = (byte)((flat[idx] & mask) | chunkVal);
            bitIdx += depth;
        }

        return SaveImage(flat, channels, width, height);
    }

    public static byte[] Decode(byte[] stegoBytes, int depth = 1, string? key = null)
    {
        var (_, _, _, flat) = LoadChannels(stegoBytes);
        var indices = PolymorphicIndex.BuildIndices(flat.Length, key);

        int headerBitsNeeded = HeaderSize * 8;
        var headerBits = ExtractBits(flat, indices, depth, headerBitsNeeded);
        if (headerBits.Count < headerBitsNeeded)
            throw new InvalidDataException("Carrier too small to contain a valid payload header");

        uint length = BinaryPrimitives.ReadUInt32BigEndian(BitsToBytes(headerBits, headerBitsNeeded));
        if (length == 0 || length > 100_000_000)
            throw new InvalidDataException($"Invalid payload length in header: {length}");

        int totalBitsNeeded = (HeaderSize + (int)length) * 8;
        var allBits = ExtractBits(flat, indices, depth, totalBitsNeeded);
        if (allBits.Count < totalBitsNeeded)
            throw new InvalidDataException("Carrier does not contain enough data for declared payload length");

        var payloadBits = allBits.GetRange(headerBitsNeeded, totalBitsNeeded - headerBitsNeeded);
        return BitsToBytes(payloadBits, payloadBits.Count);
    }

    // ── Bit manipulation helpers ────────────────────────────────────────────

    private static byte[] BytesToBits(byte[] data)
    {
        var bits = new byte[data.Length * 8];
        int k = 0;
        foreach (var b in data)
            for (int i = 7; i >= 0; i--)
                bits[k++] = (byte)((b >> i) & 1);
        return bits;
    }

    private static List<int> ExtractBits(byte[] flat, int[] indices, int depth, int bitsNeeded)
    {
        var bits = new List<int>(bitsNeeded);
        foreach (var idx in indices)
        {
            if (bits.Count >= bitsNeeded) break;
            byte val = flat[idx];
            for (int bitPos = depth - 1; bitPos >= 0; bitPos--)
                bits.Add((val >> bitPos) & 1);
        }
        return bits;
    }

    private static byte[] BitsToBytes(List<int> bits, int take)
    {
        int byteCount = take / 8;
        var result = new byte[byteCount];
        for (int i = 0; i < byteCount; i++)
        {
            int val = 0;
            for (int j = 0; j < 8; j++) val = (val << 1) | bits[i * 8 + j];
            result[i] = (byte)val;
        }
        return result;
    }

    // ── Image <-> flat channel buffer ───────────────────────────────────────

    private static (int Channels, int Width, int Height, byte[] Flat) LoadChannels(byte[] bytes)
    {
        IImageFormat format = Image.DetectFormat(bytes);
        using var image = Image.Load<Rgba32>(bytes);

        int channels = 4;
        if (format is PngFormat)
        {
            var meta = image.Metadata.GetPngMetadata();
            channels = meta.ColorType switch
            {
                PngColorType.Rgb => 3,
                PngColorType.RgbWithAlpha => 4,
                _ => 4, // grayscale/palette: fall back to RGBA (PIL's L/LA/P handling is not replicated)
            };
        }

        int width = image.Width, height = image.Height;
        var flat = new byte[width * height * channels];

        image.ProcessPixelRows(accessor =>
        {
            int offset = 0;
            for (int y = 0; y < accessor.Height; y++)
            {
                var row = accessor.GetRowSpan(y);
                for (int x = 0; x < row.Length; x++)
                {
                    var px = row[x];
                    flat[offset++] = px.R;
                    flat[offset++] = px.G;
                    flat[offset++] = px.B;
                    if (channels == 4) flat[offset++] = px.A;
                }
            }
        });

        return (channels, width, height, flat);
    }

    private static byte[] SaveImage(byte[] flat, int channels, int width, int height)
    {
        using var ms = new MemoryStream();
        var encoder = new PngEncoder
        {
            ColorType = channels == 4 ? PngColorType.RgbWithAlpha : PngColorType.Rgb,
        };

        if (channels == 4)
        {
            using var img = new Image<Rgba32>(width, height);
            img.ProcessPixelRows(accessor =>
            {
                int offset = 0;
                for (int y = 0; y < accessor.Height; y++)
                {
                    var row = accessor.GetRowSpan(y);
                    for (int x = 0; x < row.Length; x++)
                    {
                        row[x] = new Rgba32(flat[offset], flat[offset + 1], flat[offset + 2], flat[offset + 3]);
                        offset += 4;
                    }
                }
            });
            img.Save(ms, encoder);
        }
        else
        {
            using var img = new Image<Rgb24>(width, height);
            img.ProcessPixelRows(accessor =>
            {
                int offset = 0;
                for (int y = 0; y < accessor.Height; y++)
                {
                    var row = accessor.GetRowSpan(y);
                    for (int x = 0; x < row.Length; x++)
                    {
                        row[x] = new Rgb24(flat[offset], flat[offset + 1], flat[offset + 2]);
                        offset += 3;
                    }
                }
            });
            img.Save(ms, encoder);
        }

        return ms.ToArray();
    }
}
