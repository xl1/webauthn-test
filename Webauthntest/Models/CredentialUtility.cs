using System;
using System.Security.Cryptography;

namespace Webauthntest.Models
{
    public static class CredentialUtility
    {
        public static byte[] CreateChallenge()
        {
            var bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
                return bytes;
            }
        }

        public static byte[] Base64UrlDecode(string base64url)
        {
            var padding = new string('=', 3 & -base64url.Length);
            var base64 = base64url.Replace('-', '+').Replace('_', '/') + padding;
            return Convert.FromBase64String(base64);
        }

        public static byte[] Hash(byte[] source)
        {
            using (var hash = SHA256.Create())
                return hash.ComputeHash(source);
        }
    }
}
