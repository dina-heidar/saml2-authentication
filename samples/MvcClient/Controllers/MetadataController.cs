using MediatR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MvcClient.Features.Metadata;
using Saml.MetadataBuilder;
using Saml.MetadataBuilder.Constants;
using System.Security.Cryptography.X509Certificates;

namespace MvcClient.Controllers
{
    public class MetadataController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IMediator _mediator;

        public MetadataController(ILogger<HomeController> logger, IMediator mediator)
        {
            _logger = logger;
            _mediator = mediator;
        }

        [HttpGet]
        public async Task<IActionResult> Create()
        {
            // var spCertificate = ; 
            var sp = new BasicSpMetadata
            {
                EncryptingCertificate = new EncryptingCertificate
                {
                    EncryptionCertificate = new X509Certificate2("certificates/dev.govalerts.la.gov/dev.govalerts.la.gov.pfx", "0n3wh33L", X509KeyStorageFlags.Exportable),
                    //AcceptedEncryptionMethods = new EncryptionMethod[]
                    //{
                    //    new EncryptionMethod
                    //    {
                    //        Algorithm =SecurityAlgorithms.Aes128Encryption
                    //    },
                    //    new EncryptionMethod
                    //    {
                    //        Algorithm =SecurityAlgorithms.Aes256Encryption
                    //    },

                    //    new EncryptionMethod
                    //    {
                    //        Algorithm ="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                    //    }
                    //}
                },
                SigningCertificate = new X509Certificate2("certificates/stage.govalerts.la.gov/stage.govalerts.la.gov.pfx", "0n3wh33L", X509KeyStorageFlags.Exportable),
                EntityID = "dev.contoso.com",
                AssertionConsumerService = AssertionConsumerServiceExtensions.Post.Url("https://dev.contoso.com/signin", 0),
                SingleLogoutServiceEndpoint = SingleLogoutServiceTypes.Post.Url("https://dev.contoso.com/signout"),
                AuthnRequestsSigned = true,
                Signature = new X509Certificate2("certificates/stage.govalerts.la.gov/stage.govalerts.la.gov.pfx", "0n3wh33L", X509KeyStorageFlags.UserKeySet),

                //Signature = new X509Certificate2("certificates/ecdsa/ECDSAtestsigning.identity.goea.la.gov.pfx", "0n3wh33L", X509KeyStorageFlags.UserKeySet),

                ContactPersons = new ContactPerson[]
                {
                    new ContactPerson
                    {
                        GivenName = "Dina",
                        Surname = "Heidar",
                        Company = "OTS",
                        ContactType = ContactEnumType.Technical,
                        EmailAddresses = new []{"dina.heidar@la.gov"},
                        TelephoneNumbers = new []{"225-123-1234"}
                    }
                },
                //Extensions = new Extension
                //{
                //    Any = new object[] {
                //            new UiInfo
                //        {
                //            Description = new LocalizedName { Language = "en-US", Value = "A test OTS site" },
                //            DisplayName = new LocalizedName { Language = "en-US", Value = "OTS" },
                //            Keywords = new Keyword { Language = "en-US", Values = new[] { "ots saml hello" } }
                //        },
                //              new UiInfo
                //        {
                //            Description = new LocalizedName { Language = "fr", Value = "OTSier" },
                //            DisplayName = new LocalizedName { Language = "fr", Value = "OTSir disply" },
                //            Keywords = new Keyword { Language = "en-US", Values = new[] { "ots francais saml hallo" } }
                //        },
                //              //http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.html
                //              new DigestMethod
                //              {
                //                  Algorithm = SecurityAlgorithms.Sha384Digest
                //              },
                //               new DigestMethod
                //              {
                //                  Algorithm = SecurityAlgorithms.Sha256Digest
                //              },
                //                new DigestMethod
                //              {
                //                  Algorithm = SecurityAlgorithms.Sha384Digest
                //              },
                //                new SigningMethod
                //                {
                //                    Algorithm = SecurityAlgorithms.EcdsaSha256Signature, //http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
                //                    MaxKeySize= "511",
                //                    MinKeySize= "256"
                //                },
                //                new SigningMethod
                //                {
                //                    Algorithm = SecurityAlgorithms.RsaSha256Signature, //http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
                //                    MaxKeySize= "4096",
                //                    MinKeySize= "2048"
                //                }
                //    }
                //},
                WantAssertionsSigned = true,

                Organization = new Organization
                {
                    OrganizationDisplayName = new LocalizedName[] { new LocalizedName { Language = "en-US", Value = "Office of technology services" } },
                    OrganizationName = new LocalizedName[] { new LocalizedName { Language = "en-US", Value = "DOA OTS" } },
                    OrganizationURL = new[] { new LocalizedUri { Language = "en-US", Uri = new Uri("https://ots.la.gov") } }
                },
                NameIdFormat = NameIdFormatTypes.Email,
                CacheDuration = "PT604800S",
                Id = $"_{Guid.NewGuid()}",
                ServiceNames = new LocalizedName[] { new LocalizedName { Language = "en-US", Value = "IdentityServer test" } },
                ServiceDescriptions = new LocalizedName[] { new LocalizedName { Language = "en-US", Value = "IdentityServer description" } },
                RequestedAttributes = new RequestedAttribute[] {
                    new RequestedAttribute
                    {
                        IsRequiredField = true,
                        NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                        Name= "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                        FriendlyName = "Name"
                    },
                   new RequestedAttribute
                    {
                        IsRequiredField = true,
                        NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                        Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                        FriendlyName = "E-Mail-Adresses"
                    },
                }
                // Signature = new Signature { }
            };
            var xml = await _mediator.Send(new Create.Command
            {
                ServiceProviderMetadata = sp
            });

            return View(xml);
        }

        [HttpPost]
        public async Task<IActionResult> Create(Create.Command command,
            CancellationToken cancellationToken)
        {
            var xml = await _mediator.Send(command, cancellationToken);
            return View();
        }
    }
}