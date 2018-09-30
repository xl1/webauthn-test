using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PeterO.Cbor;

namespace Webauthntest.Models
{
    public class FIDOU2FAttestationStatement
    {
        public byte[][] X509Cert { get; set; }
        public byte[] Signature { get; set; }

        public static FIDOU2FAttestationStatement Decode(CBORObject obj)
        {
            var x5c = obj["x5c"];
            var cert = Enumerable.Range(0, x5c.Count).Select(i => x5c[i]?.GetByteString());
            return new FIDOU2FAttestationStatement
            {
                X509Cert = cert.ToArray(),
                Signature = obj["sig"]?.GetByteString(),
            };
        }

        public bool VerifyData(byte[] data)
        {
            if (X509Cert == null || X509Cert.Length != 1)
                return false;

            if (Signature == null)
                return false;

            var rawSignature = DERSignature.Deserialize(Signature);
            var ecDsa = new X509Certificate2(X509Cert[0]).GetECDsaPublicKey();
            return ecDsa.VerifyData(data, rawSignature, HashAlgorithmName.SHA256);
        }
    }
}
