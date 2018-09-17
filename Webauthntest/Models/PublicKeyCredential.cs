namespace Webauthntest.Models
{
    public class PublicKeyCredential
    {
        public string Name { get; set; }
        public uint SignCounter { get; set; }
        public byte[] CredentialId { get; set; }
        public byte[] PublicKey { get; set; }
    }
}
