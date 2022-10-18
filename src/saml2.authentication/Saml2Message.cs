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
using System.Xml;
using System.Xml.Serialization;
using MetadataBuilder.Schema.Metadata;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Saml.MetadataBuilder;
using static Saml2Core.Saml2Constants;

namespace Saml2Core
{
    public class Saml2Message : AuthenticationProtocolMessage
    {
        public static Saml2Message CreateSignInRequest(Saml2Options options)
        {           
            //AuthnRequest ID value which needs to be included in the AuthnRequest
            //we will need this to create the same session cookie as well
            var authnRequestId = Microsoft.IdentityModel.Tokens.UniqueId.CreateRandomId();

            var idpSingleServiceSignOnEndpoints = (options.Configuration.Items
                   .FirstOrDefault(i => i.GetType() == typeof(IDPSSODescriptor)) as IDPSSODescriptor)
                   .SingleSignOnServices;

            var authnRequest = new AuthnRequestType()
            {
                ID = authnRequestId,
                Issuer = new NameIDType()
                {
                    Format = options.NameId.Format,
                    Value = options.EntityId,
                    SPProvidedID = options.NameId.SpProvidedId,
                    SPNameQualifier = options.NameId.SpNameQualifier,
                    NameQualifier = options.NameId.NameQualifier
                },
                NameIDPolicy = new NameIDPolicyType()
                {
                    Format = options.NameId.Format,
                    SPNameQualifier = options.NameId.SpNameQualifier,
                    AllowCreate = true,
                    AllowCreateSpecified = true
                },
                Version = Saml2Constants.Version,
                ForceAuthn = options.ForceAuthn,
                ForceAuthnSpecified = true,
                IsPassive = options.IsPassive,
                IsPassiveSpecified = true,
                AssertionConsumerServiceIndex = options.AssertionConsumerServiceIndex,
                AssertionConsumerServiceURL = options.AssertionConsumerServiceUrl.AbsoluteUri,
                ProtocolBinding = GetProtocolBinding(options.ResponseProtocolBinding),
                IssueInstant = DateTime.UtcNow,
                Destination = GetSignOnEndpoint(idpSingleServiceSignOnEndpoints, options.AuthenticationMethod)
            };

            //create xml
            var authnRequestXmlDoc = Serialize<AuthnRequestType>(authnRequest);

            //if post method and needs signature then
            //sign it
            if (options.AuthenticationMethod == Saml2AuthenticationBehaviour.FormPost)
            {

            }
            var authnRequestBase64 = 
        }

        public string SamlRequest { get; set; }
        public string Relay { get; set; }
        public string SigAlg { get; set; }
        public string Signature { get; set; }

        #region Private 

        public static XmlDocument Serialize<T>(T item) where T : class
        {
            var xmlTemplate = string.Empty;
            var xmlSerializer = new XmlSerializer(typeof(T));
            using (var memStm = new MemoryStream())
            {
                xmlSerializer.Serialize(memStm, item);
                memStm.Position = 0;
                xmlTemplate = new StreamReader(memStm).ReadToEnd();
            }
            //create xml document from string
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlTemplate);
            xmlDoc.PreserveWhitespace = true;
            return xmlDoc;
        }
        private static string GetProtocolBinding(Saml2ResponseProtocolBinding responseProtocolBinding)
        {
            switch (responseProtocolBinding)
            {
                case Saml2ResponseProtocolBinding.FormPost:
                    {
                        return ProtocolBindings.HTTP_Post;
                    }
                case Saml2ResponseProtocolBinding.Artifact:
                    {
                        return ProtocolBindings.HTTP_Artifact;
                    }
                default:
                    return ProtocolBindings.HTTP_Post;
            }
        }
        private static string GetSignOnEndpoint(Endpoint[] signOnEndpoints, Saml2AuthenticationBehaviour method)
        {
            if (method == Saml2AuthenticationBehaviour.RedirectGet)
            {
                return signOnEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Redirect).Location;
            }
            else
            {
                return signOnEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Post).Location;
            }
        }
        #endregion
    }
}
