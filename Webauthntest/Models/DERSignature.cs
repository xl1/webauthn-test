using System;

namespace Webauthntest.Models
{
    public static class DERSignature
    {
        public static Span<byte> Deserialize(Span<byte> s)
        {
            // SEQ      s[0] == 0x30
            // (length) s[1]
            // INTEGER  s[2] == 0x02
            byte rlen = s[3];
            var vr = RemoveAnyNegativeFlag(s.Slice(4, rlen));

            // INTEGER  s[4 + b2] == 0x02;
            byte slen = s[5 + rlen];
            var vs = RemoveAnyNegativeFlag(s.Slice(6 + rlen, slen));

            var parsedSignature = new Span<byte>(new byte[vr.Length + vs.Length]);
            vr.CopyTo(parsedSignature);
            vs.CopyTo(parsedSignature.Slice(vr.Length));
            return parsedSignature;
        }

        private static Span<byte> RemoveAnyNegativeFlag(Span<byte> input)
        {
            return input[0] == 0 ? input.Slice(1) : input;
        }
    }
}
