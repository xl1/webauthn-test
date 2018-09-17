using System;
using System.IO;

namespace Webauthntest.Models
{
    public static class DERSignature
    {
        public static byte[] Deserialize(byte[] s)
        {
            // https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1
            using (var ms = new MemoryStream(s))
            {
                var header = ms.ReadByte();
                var b1 = ms.ReadByte();

                var markerR = ms.ReadByte();
                var b2 = ms.ReadByte();
                var vr = new byte[b2];
                ms.Read(vr, 0, vr.Length);
                vr = RemoveAnyNegativeFlag(vr);

                var markerS = ms.ReadByte();
                var b3 = ms.ReadByte();
                var vs = new byte[b3];
                ms.Read(vs, 0, vs.Length);
                vs = RemoveAnyNegativeFlag(vs);

                var parsedSignature = new byte[vr.Length + vs.Length];
                vr.CopyTo(parsedSignature, 0);
                vs.CopyTo(parsedSignature, vr.Length);

                return parsedSignature;
            }
        }

        private static byte[] RemoveAnyNegativeFlag(byte[] input)
        {
            if (input[0] != 0) return input;

            var output = new byte[input.Length - 1];
            Array.Copy(input, 1, output, 0, output.Length);
            return output;
        }
    }
}
