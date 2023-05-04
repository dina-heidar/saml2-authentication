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
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Saml2Metadata;
using Saml2Metadata.Schema;

namespace Saml2Authentication
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
                    var pattern = @"^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$";
                    var result = Regex.IsMatch(options.MetadataAddress,
                        pattern, RegexOptions.IgnoreCase);

                    if (result)
                    {
                        var httpsPattern = @"^(https:\/\/www\.|https:\/\/)[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$";
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

                // if there is an existing metadata file with the
                // same configured name then don't create it
                if (xmlList.Length > 0 &&
                     xmlList.Contains(Path.Combine(options.DefaultMetadataFolderLocation,
                     options.DefaultMetadataFileName + ".xml")))
                {
                    // the file exists and will
                    // need to be manually deleted first
                    return;
                }
                else
                {
                    var request = _httpContextAccessor.HttpContext.Request;
                    var bsm = MetadataExtensions.Generate(options, request);

                    //output as xml
                    var xmlDoc = _writer.Output(bsm);

                    //validate the saml sp metadata file
                    //if (options.ValidateMetadata)
                    //{
                    //    _writer.Validate(xmlDoc);
                    //}

                    //save
                    xmlDoc.Save(Path.Combine(options.DefaultMetadataFolderLocation,
                        options.DefaultMetadataFileName + ".xml"));
                }
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

