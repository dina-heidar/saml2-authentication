﻿// Copyright (c) 2019 Dina Heidar
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
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using MetadataBuilder.Schema.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Saml.MetadataBuilder;

namespace Saml2Core
{
    internal class Saml2PostConfigureOptions : IPostConfigureOptions<Saml2Options>
    {
        private readonly IDocumentRetriever _idoc;
        private readonly IDataProtectionProvider _dp;
        private readonly IMetadataMapper<EntityDescriptorType, EntityDescriptor> _mapper;

        public Saml2PostConfigureOptions(IDataProtectionProvider dataProtection,
            IDocumentRetriever idoc,
            IMetadataMapper<EntityDescriptorType, EntityDescriptor> mapper)
        {
            _dp = dataProtection;
            _idoc = idoc;
            _mapper = mapper;
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

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(Saml2Handler).FullName!, name, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
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
