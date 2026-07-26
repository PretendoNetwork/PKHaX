using System.Buffers;

namespace PKHaX;

public static class SequenceReaderExtensions {
    /// <summary>
    /// Advance the reader so it aligns to specific bytes.
    /// 
    /// Example: If reader is at offset 3 and you align to every 4 bytes. It'll advance 1.
    /// </summary>
    public static void Align<T>(this SequenceReader<T> reader, long alignment) where T : unmanaged, IEquatable<T>
    {
        var advancementAmount = alignment - (reader.Consumed % alignment);
        if (advancementAmount < alignment)
        {
            reader.Advance(advancementAmount);
        }
    }
}
