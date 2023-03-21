// Copyright (c) 2019 Dina Heidar
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
//
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM
//
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using MetadataBuilder.Schema.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Saml.MetadataBuilder;
using Saml2Core.Metadata;

namespace Saml2Core
{
    internal class Saml2PostConfigureOptions : IPostConfigureOptions<Saml2Options>
    {
        private readonly IDocumentRetriever _idoc;
        private readonly IDataProtectionProvider _dp;
        private readonly IMetadataMapper<EntityDescriptorType, EntityDescriptor> _mapper;
        private readonly IMetadataWriter _writer;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public Saml2PostConfigureOptions(IDataProtectionProvider dataProtection,
            IDocumentRetriever idoc,
            IMetadataMapper<EntityDescriptorType, EntityDescriptor> mapper,
            IMetadataWriter writer,
            IHttpContextAccessor httpContextAccessor)
        {
            _dp = dataProtection;
            _idoc = idoc;
            _mapper = mapper;
            _writer = writer;
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Invoked to post configure a TOptions instance.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        /// <exception cref="InvalidOperationException">
        /// Service Provider certificate could not be found.
        /// or
        /// Multiple Service Provider certificates were found, must only provide one.
        /// or
        /// The certificate for this service providerhas no private key.
        /// or
        /// The MetadataAddress must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.
        /// </exception>
        public void PostConfigure(string name, Saml2Options options)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;

            if (string.IsNullOrEmpty(options.SignOutScheme))
            {
                options.SignOutScheme = options.SignInScheme;
            }

            if (options.SigningCertificate != null && !options.SigningCertificate.HasPrivateKey)
            {
                throw new Saml2Exception("Service provider signing certificate does not have a private key");
            }

            if (options.EncryptingCertificate != null && options.EncryptingCertificate.GetRSAPrivateKey() == null)
            {
                throw new Saml2Exception("Service provider ecryption certificate must be an RSA certificate.");
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(Saml2Handler).FullName!, name, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (options.AssertionConsumerServiceIndex != null)
            {
                options.AssertionConsumerServiceUrl = null;
            }

            if (options.StringDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(Saml2Handler).FullName!,
                    typeof(string).FullName!,
                    name,
                    "v1");

                options.StringDataFormat = new SecureDataFormat<string>(new StringSerializer(), dataProtector);
            }

            // set the token validation audience 
            if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience) &&
                !string.IsNullOrEmpty(options.EntityId))
            {
                options.TokenValidationParameters.ValidAudience = options.EntityId;
            }

            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET Saml2Core handler");
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    options.ConfigurationManager =
                        new StaticConfigurationManager<EntityDescriptor>(options.Configuration);
                }
                else if (!string.IsNullOrEmpty(options.MetadataAddress))
                {
                    var pattern = @"(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$";
                    var result = Regex.IsMatch(options.MetadataAddress,
                        pattern, RegexOptions.IgnoreCase);

                    if (result)
                    {
                        var httpsPattern = @"^(https:\/\/www\.|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$";
                        var isHttpsRegexMatch = Regex.IsMatch(options.MetadataAddress, httpsPattern, RegexOptions.IgnoreCase);

                        if (options.RequireHttpsMetadata && !isHttpsRegexMatch)
                        {
                            throw new Saml2Exception("The MetadataAddress must use 'https' unless disabled for development by setting RequireHttpsMetadata=false.");
                        }
                        options.ConfigurationManager = new ConfigurationManager<EntityDescriptor>
                            (options.MetadataAddress, new MetadataReader(_mapper),
                           new HttpDocumentRetriever(options.Backchannel)
                           {
                               RequireHttps = options.RequireHttpsMetadata
                           });
                    }
                    else
                    {
                        _idoc.GetDocumentAsync(options.MetadataAddress, default(CancellationToken));
                        options.ConfigurationManager = new ConfigurationManager<EntityDescriptor>(options.MetadataAddress,
                            new MetadataReader(_mapper), _idoc);
                    }

                    if (options.ResponseProtocolBinding == Saml2ResponseProtocolBinding.Artifact && options.SigningCertificate == null)
                    {
                        throw new Saml2Exception("Signing certifactes are required when using 'HTTP-Artifact' binding protocol");
                    }
                }
            }

            //create metadata.xml if set to true
            if (options.CreateMetadataFile)
            {
                //check if the metadata.xml already exists
                string[] xmlList = Directory.GetFiles(options.DefaultMetadataFolderLocation, "*.xml");

                if (xmlList.Length > 0)
                {
                    // the file exists and will
                    // need to be manually deleted first
                    return;
                }
                else
                {
                    var bsm = new BasicSpMetadata
                    {
                        Signature = options.Metadata.Signature,
                        ContactPersons = new ContactPerson[]
                        {
                            new ContactPerson
                            {
                                Company =  options.Metadata.ContactPersons.Company,
                                ContactType =  options.Metadata.ContactPersons.ContactType,
                                EmailAddresses = new[]{  options.Metadata.ContactPersons.EmailAddress },
                                TelephoneNumbers = new []{ options.Metadata.ContactPersons.TelephoneNumber},
                                GivenName =  options.Metadata.ContactPersons.GivenName,
                                Surname= options.Metadata.ContactPersons.Surname
                            }
                        },
                        Organization = new Organization
                        {
                            OrganizationDisplayName = new LocalizedName[] { new LocalizedName { Language = options.Metadata.Organization.Language,
                                Value = options.Metadata.Organization.OrganizationDisplayName } },
                            OrganizationName = new LocalizedName[] { new LocalizedName { Language = options.Metadata.Organization.Language,
                                Value = options.Metadata.Organization.OrganizationName } },
                            OrganizationURL = new[] { new LocalizedUri { Language = options.Metadata.Organization.Language,
                                Uri = options.Metadata.Organization.OrganizationURL } }
                        },
                        Extensions = new Extension
                        {
                            Any = new object[]
                           {
                               new UiInfo
                               {
                                   InformationURL = new LocalizedUri { Language = options.Metadata.UiInfo.Language,
                                       Uri = options.Metadata.UiInfo.InformationURL },
                                   DisplayName = new LocalizedName { Language = options.Metadata.UiInfo.Language,
                                       Value = options.Metadata.UiInfo.DisplayName },
                                   Description = new LocalizedName { Language = options.Metadata.UiInfo.Language,
                                       Value = options.Metadata.UiInfo.Description },
                                   PrivacyStatementURL = new LocalizedUri { Language = options.Metadata.UiInfo.Language,
                                       Uri = options.Metadata.UiInfo.PrivacyStatementURL },
                                   Logo = new Logo
                                   {
                                       Height = options.Metadata.UiInfo.LogoHeight,
                                       Width = options.Metadata.UiInfo.LogoWidth,
                                       Value = options.Metadata.UiInfo.LogoUriValue,
                                       Language = options.Metadata.UiInfo.Language
                                   },
                                   Keywords = new Keyword
                                   {
                                      Language=options.Metadata.UiInfo.Language,
                                      Values= options.Metadata.UiInfo.KeywordValues
                                   },
                               }
                           }
                        },

                        //internals
                        EntityID = options.EntityId,
                        NameIdFormat = options.NameIdPolicy.Format,
                        AuthnRequestsSigned = options.AuthenticationRequestSigned,
                        WantAssertionsSigned = options.WantAssertionsSigned,
                        SigningCertificate = options.SigningCertificate,
                        EncryptingCertificate = new EncryptingCertificate
                        {
                            EncryptionCertificate = options.EncryptingCertificate
                        },
                        AssertionConsumerService = GetAssertionConsumerService(options.ResponseProtocolBinding, options.CallbackPath),
                        SingleLogoutServiceEndpoint = GetSingleLogoutServiceEndpoint(options.ResponseLogoutBinding, options.SignOutPath),
                    };

                    var xmlDoc = _writer.Output(bsm);
                    xmlDoc.Save(System.IO.Path.Combine(options.DefaultMetadataFolderLocation, options.DefaultMetadataFileName + ".xml"));
                }
            }
        }

        private IndexedEndpoint GetAssertionConsumerService(Saml2ResponseProtocolBinding responseProtocolBinding,
            PathString callbackPath)
        {
            var request = _httpContextAccessor.HttpContext.Request;
            var url = request.Scheme + "://" + request.Host.Value + callbackPath;

            // if post
            if (responseProtocolBinding == Saml2ResponseProtocolBinding.FormPost)
            {
                return AssertionConsumerServiceExtensions.Post.Url(url, 0, true);
            }
            //if redirect
            else
            {
                return AssertionConsumerServiceExtensions.Redirect.Url(url, 0, true);
            }
        }

        private IndexedEndpoint GetSingleLogoutServiceEndpoint(Saml2ResponseLogoutBinding responseLogoutBinding,
            PathString signoutPath)
        {
            var request = _httpContextAccessor.HttpContext.Request;
            var url = request.Scheme + "://" + request.Host.Value + signoutPath;

            // if post
            if (responseLogoutBinding == Saml2ResponseLogoutBinding.FormPost)
            {
                return SingleLogoutServiceTypes.Post.Url(url, 0, true);
            }
            //if redirect
            else
            {
                return SingleLogoutServiceTypes.Redirect.Url(url, 0, true);
            }
        }

        private sealed class StringSerializer : IDataSerializer<string>
        {
            public string Deserialize(byte[] data)
            {
                return Encoding.UTF8.GetString(data);
            }

            public byte[] Serialize(string model)
            {
                return Encoding.UTF8.GetBytes(model);
            }

        }
    }
}

