using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Webauthntest.Models
{
    public class CredentialRepository
    {
        private static readonly ConcurrentBag<PublicKeyCredential> _data =
            new ConcurrentBag<PublicKeyCredential>();

        public PublicKeyCredential Find(string name, byte[] id)
        {
            return _data
                .Where(c => c.Name == name)
                .Where(c => c.CredentialId.SequenceEqual(id))
                .FirstOrDefault();
        }

        public IReadOnlyList<PublicKeyCredential> FindByName(string name)
        {
            return _data.Where(c => c.Name == name).ToArray();
        }

        public void Add(PublicKeyCredential cred) => _data.Add(cred);
    }
}
