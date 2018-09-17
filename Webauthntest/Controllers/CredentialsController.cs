using System;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Webauthntest.Models;

namespace Webauthntest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CredentialsController : ControllerBase
    {
        private readonly CredentialRepository _credentialRepository;

        public CredentialsController(CredentialRepository credentialRepository)
        {
            _credentialRepository = credentialRepository;
        }

        public class RegistrationRequest
        {
            public string Id { get; set; }
            public byte[] RawId { get; set; }
            public string Type { get; set; }
            public byte[] Attestation { get; set; }
            public byte[] ClientData { get; set; }
        }

        public class VerificationRequest
        {
            public string Id { get; set; }
            public byte[] RawId { get; set; }
            public string Type { get; set; }
            public byte[] AuthData { get; set; }
            public byte[] ClientData { get; set; }
            public byte[] Signature { get; set; }
        }

        private string RelyingPartyId => new Uri(Request.GetDisplayUrl()).Host; // localhost

        [HttpPost("challenge")]
        public ActionResult<object> GenerateChallenge(string name)
        {
            var rpid = RelyingPartyId;
            var challenge = CredentialUtility.CreateChallenge();
            HttpContext.Session.Set("name", Encoding.UTF8.GetBytes(name));
            HttpContext.Session.Set("challenge", challenge);

            return new
            {
                relyingPartyId = rpid,
                relyingParty = rpid,
                challenge
            };
        }

        [HttpPost("register")]
        public ActionResult<object> Register(RegistrationRequest req)
        {
            var session = HttpContext.Session;
            var origin = $"{Request.Scheme}://{Request.Host}"; // https://localhost:12345
            if (session.TryGetValue("challenge", out byte[] challenge) &&
                session.TryGetValue("name", out byte[] nameBytes))
            {
                var name = Encoding.UTF8.GetString(nameBytes);
                var clientData = CredentialRegistration.ValidateClientData(req.ClientData, origin, challenge);
                var verifiedCredential = CredentialRegistration.ValidateAttestationData(name, req.Attestation, RelyingPartyId);

                // save
                _credentialRepository.Add(verifiedCredential);

                return new
                {
                    clientData,
                };
            }

            throw new Exception("session expired");
        }

        [HttpPost("assertion")]
        public ActionResult<object> GetAssertion(string name)
        {
            var challenge = CredentialUtility.CreateChallenge();
            HttpContext.Session.Set("name", Encoding.UTF8.GetBytes(name));
            HttpContext.Session.Set("challenge", challenge);

            return new
            {
                relyingPartyId = RelyingPartyId,
                challenge,
                allowCredentials = _credentialRepository
                    .FindByName(name)
                    .Select(c => new
                    {
                        type = "public-key",
                        id = c.CredentialId,
                    })
            };
        }

        [HttpPost("verify")]
        public ActionResult<object> Verify(VerificationRequest req)
        {
            var session = HttpContext.Session;
            var origin = $"{Request.Scheme}://{Request.Host}"; // https://localhost:12345
            if (session.TryGetValue("challenge", out byte[] challenge) &&
                session.TryGetValue("name", out byte[] nameBytes))
            {
                var name = Encoding.UTF8.GetString(nameBytes);
                var clientData = CredentialVerification.ValidateClientData(req.ClientData, origin, challenge);

                var credential = _credentialRepository.Find(name, req.RawId);
                if (credential == null)
                {
                    throw new Exception("user not found");
                }

                CredentialVerification.VerifySignature(credential, req.AuthData, req.ClientData, req.Signature, RelyingPartyId);
                return new
                {
                    clientData,
                };
            }

            throw new Exception("session expired");
        }
    }
}
