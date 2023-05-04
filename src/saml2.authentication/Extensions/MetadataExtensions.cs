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

using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Saml2Metadata;

namespace Saml2Authentication
{
    internal static class MetadataExtensions
    {
        public static BasicSpMetadata Generate(Saml2Options options, HttpRequest request)
        {
            var bsm = new BasicSpMetadata();

            bsm.Id = options.Metadata.Id;
            bsm.ValidUntil = options.Metadata.ValidUntil;
            bsm.CacheDuration = options.Metadata.CacheDuration;
            bsm.Signature = options.Metadata.Signature;

            if (options.Metadata.ContactPersons != null)
            {
                bsm.ContactPersons = new Saml2Metadata.ContactPerson[]
                {
                    new Saml2Metadata.ContactPerson
                    {
                        Company =  options.Metadata.ContactPersons.Company,
                        ContactType =  ContactTypeExtensions.ToContactEnumType(options.Metadata.ContactPersons.ContactType),
                        EmailAddresses = new[]{  options.Metadata.ContactPersons.EmailAddress },
                        TelephoneNumbers = new []{ options.Metadata.ContactPersons.TelephoneNumber},
                        GivenName =  options.Metadata.ContactPersons.GivenName,
                        Surname= options.Metadata.ContactPersons.Surname
                    }
                };
            }

            if (options.Metadata.Organization != null)
            {
                bsm.Organization = new Saml2Metadata.Organization
                {
                    OrganizationDisplayName = new LocalizedName[] { new LocalizedName { Language = options.Metadata.Organization.Language,
                                Value = options.Metadata.Organization.OrganizationDisplayName } },
                    OrganizationName = new LocalizedName[] { new LocalizedName { Language = options.Metadata.Organization.Language,
                                Value = options.Metadata.Organization.OrganizationName } },
                    OrganizationURL = new[] { new LocalizedUri { Language = options.Metadata.Organization.Language,
                                Uri = options.Metadata.Organization.OrganizationURL } }
                };
            }

            if (options.Metadata.UiInfo != null)
            {
                bsm.Extensions = new Extension
                {
                    Any = new object[]
                    {
                        new Saml2Metadata.UiInfo
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
                                Language= options.Metadata.UiInfo.Language,
                                Values= options.Metadata.UiInfo.KeywordValues
                            },
                        }
                    }
                };
            }

            if (options.Metadata.AttributeConsumingService != null)
            {
                bsm.AttributeConsumingService = new Saml2Metadata.AttributeConsumingService[]
                {
                    new Saml2Metadata.AttributeConsumingService
                    {
                        Index = 0,
                        IsDefault= true,
                        IsDefaultFieldSpecified = true,
                        ServiceDescriptions = new LocalizedName[]{ new LocalizedName { Language = options.Metadata.AttributeConsumingService.Language,
                            Value =options.Metadata.AttributeConsumingService.ServiceDescriptions } },
                        ServiceNames = new LocalizedName[]{ new LocalizedName { Language = options.Metadata.AttributeConsumingService.Language,
                            Value =options.Metadata.AttributeConsumingService.ServiceNames } },
                        RequestedAttributes = GetRequestedAttributes(options.Metadata.AttributeConsumingService.RequestedAttributes)
                    }
                };
            }

            //internals
            bsm.EntityID = options.EntityId;
            bsm.NameIdFormat = options.NameIdPolicy.Format;
            bsm.AuthnRequestsSigned = options.AuthenticationRequestSigned;
            bsm.WantAssertionsSigned = options.WantAssertionsSigned;
            bsm.SigningCertificate = options.SigningCertificate;
            bsm.EncryptingCertificate = new EncryptingCertificate
            {
                EncryptionCertificate = options.EncryptingCertificate
            };
            bsm.AssertionConsumerService = GetAssertionConsumerService(options.ResponseProtocolBinding, options.CallbackPath, request);
            bsm.SingleLogoutServiceEndpoint = GetSingleLogoutServiceEndpoint(options.ResponseLogoutBinding, options.SignOutPath, request);

            return bsm;
        }

        private static IndexedEndpoint GetAssertionConsumerService(Saml2ResponseProtocolBinding responseProtocolBinding,
           PathString callbackPath, HttpRequest request)
        {
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

        private static IndexedEndpoint GetSingleLogoutServiceEndpoint(Saml2ResponseLogoutBinding responseLogoutBinding,
            PathString signoutPath, HttpRequest request)
        {
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
        private static Saml2Metadata.RequestedAttribute[] GetRequestedAttributes(RequestedAttribute[] reqs)
        {
            var requestedAttributes = new List<Saml2Metadata.RequestedAttribute>();
            foreach (var req in reqs)
            {
                requestedAttributes.Add(new Saml2Metadata.RequestedAttribute
                {
                    Name = req.Name,
                    NameFormat = req.NameFormat,
                    FriendlyName = req.FriendlyName,
                    AttributeValue = req.AttributeValue,
                    IsRequiredField = req.IsRequiredField,
                    IsRequiredFieldSpecified = req.IsRequiredFieldSpecified
                });
            }
            return requestedAttributes.ToArray();
        }
    }
}
