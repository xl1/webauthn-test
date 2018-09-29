﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PeterO.Cbor;
using Utf8Json;

namespace Webauthntest.Models
{
    public class ClientData
    {
        public string Type { get; set; }
        public string Origin { get; set; }
        public string Challenge { get; set; } // base64url
    }

    [Flags]
    public enum AuthenticatorDataFlags
    {
        UserPresent = 1 << 0,
        UserVerified = 1 << 2,
        AttestedCredentialData = 1 << 6,
        ExtensionDataIncluded = 1 << 7,
    }

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

    public class CredentialRegistration
    {
        public static ClientData ValidateClientData(byte[] clientData, string origin, byte[] challenge)
        {
            var data = JsonSerializer.Deserialize<ClientData>(clientData);

            if (data.Type != "webauthn.create")
                throw new Exception($"type does not match: {data.Type}");

            if (data.Origin != origin)
                throw new Exception($"origin does not match: {data.Origin}");

            if (!CredentialUtility.Base64UrlDecode(data.Challenge).SequenceEqual(challenge))
                throw new Exception("challenge does not match");

            return data;
        }

        public static PublicKeyCredential ValidateAttestationData(string name, byte[] bytes, string rpid)
        {
            var cbor = CBORObject.DecodeFromBytes(bytes);

            var authDataSpan = cbor["authData"].GetByteString().AsSpan();
            var format = cbor["fmt"].AsString();
            var attestationStatement = cbor["attStmt"];

            var rpidHash = authDataSpan.Slice(0, 32);
            var flags = (AuthenticatorDataFlags)authDataSpan[32];

            var counterSpan = authDataSpan.Slice(33, 4);
            counterSpan.Reverse();
            uint counter = BitConverter.ToUInt32(counterSpan);

            if ((flags & AuthenticatorDataFlags.UserPresent) == 0)
                throw new Exception("user does not present");

            if ((flags & AuthenticatorDataFlags.AttestedCredentialData) == 0)
                throw new Exception("credential data does not exist");

            var aaguid = authDataSpan.Slice(37, 16);
            int credentialIdLength = (authDataSpan[53] << 8) + authDataSpan[54];
            var credentialId = authDataSpan.Slice(55, credentialIdLength);

            if (!rpidHash.SequenceEqual(CredentialUtility.Hash(Encoding.UTF8.GetBytes(rpid))))
                throw new Exception("RP ID Hash does not match");

            var credentialPublicKey = authDataSpan.Slice(55 + credentialIdLength).ToArray();

            // validate attestation
            switch (format)
            {
                case "none":
                    break;
                default:
                    throw new Exception($"unsupported attestation format: {format}");
            }

            return new PublicKeyCredential
            {
                Name = name,
                CredentialId = credentialId.ToArray(),
                PublicKey = credentialPublicKey,
            };
        }
    }

    public class CredentialVerification
    {
        public static ClientData ValidateClientData(byte[] clientData, string origin, byte[] challenge)
        {
            var data = JsonSerializer.Deserialize<ClientData>(clientData);

            if (data.Type != "webauthn.get")
                throw new Exception($"type does not match: {data.Type}");

            if (data.Origin != origin)
                throw new Exception($"origin does not match: {data.Origin}");

            if (!CredentialUtility.Base64UrlDecode(data.Challenge).SequenceEqual(challenge))
                throw new Exception("challenge does not match");

            return data;
        }

        public static void VerifySignature(PublicKeyCredential cred, byte[] authData, byte[] clientData, byte[] signature, string rpid)
        {
            if (cred == null)
                throw new ArgumentNullException(nameof(cred));

            var payload = authData.Concat(CredentialUtility.Hash(clientData)).ToArray();
            var rawSignature = DERSignature.Deserialize(signature);

            var authDataSpan = authData.AsSpan();
            var rpidHash = authDataSpan.Slice(0, 32);
            var flags = (AuthenticatorDataFlags)authDataSpan[32];

            var counterSpan = authDataSpan.Slice(33, 4);
            counterSpan.Reverse();
            uint counter = BitConverter.ToUInt32(counterSpan);

            if ((flags & AuthenticatorDataFlags.UserPresent) == 0)
                throw new Exception("user does not present");

            if (!rpidHash.SequenceEqual(CredentialUtility.Hash(Encoding.UTF8.GetBytes(rpid))))
                throw new Exception("RP ID Hash does not match");

            /*
key[CBORObject.FromObject(1)].ToString() // keytype
"2"
key[CBORObject.FromObject(3)].ToString() // algorithm
"-7"
key[CBORObject.FromObject(-1)].ToString() // curve
"1"
key[CBORObject.FromObject(-2)].ToString() // x
"h'E2DEF510883946FBBBF7AA958B6200A9863763A2383AD92F5B84F1A5A5DDCCCF'"
key[CBORObject.FromObject(-3)].ToString() // y
"h'1D7FB55C68ACA6391DCAC5C895E50150719892C86D6060BCB790FFA9855B4182'"
*/

            var publicKey = CBORObject.DecodeFromBytes(cred.PublicKey);
            var x = publicKey.MapGet(-2).GetByteString();
            var y = publicKey.MapGet(-3).GetByteString();

            var ecDsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            });
            var isValid = ecDsa.VerifyData(payload, rawSignature, HashAlgorithmName.SHA256);

            if (!isValid)
                throw new Exception("invalid signature");

            if (cred.SignCounter >= counter)
                throw new Exception("invalid signature counter");

            cred.SignCounter = counter;
        }
    }

    public static class CBORObjectExtention
    {
        public static CBORObject MapGet(this CBORObject obj, object key)
        {
            return obj[CBORObject.FromObject(key)];
        }
    }
}