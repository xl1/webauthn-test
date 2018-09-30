using System;

namespace Webauthntest.Models
{
    public ref struct ByteArrayWriter
    {
        private Span<byte> _span;
        private int _index;

        public ByteArrayWriter(int length)
        {
            _span = new byte[length];
            _index = 0;
        }

        public ByteArrayWriter Set(byte b)
        {
            _span[_index] = b;
            _index++;
            return this;
        }

        public ByteArrayWriter CopyFrom(ReadOnlySpan<byte> src)
        {
            src.CopyTo(_span.Slice(_index));
            _index += src.Length;
            return this;
        }

        public byte[] ToArray() => _span.ToArray();
    }
}
