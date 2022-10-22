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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Serialization;
using MetadataBuilder.Schema.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols;
using Saml.MetadataBuilder;
using static Saml2Core.Saml2Constants;

namespace Saml2Core
{
    public class Saml2Message : AuthenticationProtocolMessage
    {
        public Saml2Message()
        {
        }
        public Saml2Message(Saml2Message saml2Message)
        {
            if (saml2Message == null)
            {
                return;
            }

            foreach (KeyValuePair<string, string> keyValue in saml2Message.Parameters)
                SetParameter(keyValue.Key, keyValue.Value);

            IssuerAddress = saml2Message.IssuerAddress;
        }

        public string CreateSignInRequest(Saml2Options options, AuthenticationProperties properties)
        {
            //AuthnRequest ID value which needs to be included in the AuthnRequest
            //we will need this to create the same session cookie as well
            var authnRequestId = Microsoft.IdentityModel.Tokens.UniqueId.CreateRandomId();

            var idpSingleServiceSignOnEndpoints = (options.Configuration.Items
                   .FirstOrDefault(i => i.GetType() == typeof(IDPSSODescriptor)) as IDPSSODescriptor)
                   .SingleSignOnServices;
            var issuer = GetSignOnEndpoint(idpSingleServiceSignOnEndpoints, options.AuthenticationMethod);

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
                Destination = issuer
            };

            //create xml
            var authnRequestXmlDoc = Serialize<AuthnRequestType>(authnRequest);

            var saml2Message = new Saml2Message()
            {
                IssuerAddress = issuer
            };

            //relay state
            saml2Message.Relay = options.StateDataFormat.Protect(properties);

            //authentication request
            saml2Message.SamlRequest = authnRequestXmlDoc.OuterXml;

            //if post method and needs signature then we need to ign the xml itself 
            if (options.AuthenticationMethod == Saml2AuthenticationBehaviour.FormPost)
            {
                if (options.SigningCertificate != null && options.AuthenticationRequestSigned)
                {
                    var signedAuthnRequestXmlDoc = authnRequestXmlDoc.AddXmlSignature(options.SigningCertificate);
                    saml2Message.SamlRequest = signedAuthnRequestXmlDoc.OuterXml;
                }
                return saml2Message.BuildFormPost();
            }
            else
            {
                //if there is a certificate to sign the authnrequest
                if (options.SigningCertificate != null && options.AuthenticationRequestSigned)
                {
                    (var key, var signatureMethod, var keyName) =
                        XmlDocumentExtensions.SetSignatureAlgorithm(options.SigningCertificate);

                    //get signAlg
                    saml2Message.SigAlg = GetQuerySignAlg(signatureMethod);
                    var requestSignedUrlString = saml2Message.BuildRedirectUrl();

                    //get signature                
                    saml2Message.Signature = GetQuerySignature(key, requestSignedUrlString, options.SigningCertificateHashAlgorithmName);
                }
                return saml2Message.BuildRedirectUrl();
            }
        }

        public string SamlRequest
        {
            get { return GetParameter(Saml2Constants.Parameters.SamlRequest); }
            set { SetParameter(Saml2Constants.Parameters.SamlRequest, EncodeDeflateMessage(value)); }
        }
        public string Relay
        {
            get { return GetParameter(Saml2Constants.Parameters.RelayState); }
            set { SetParameter(Saml2Constants.Parameters.RelayState, EncodeDeflateMessage(value)); }
        }
        public string SigAlg
        {
            get { return GetParameter(Saml2Constants.Parameters.SigAlg); }
            set { SetParameter(Saml2Constants.Parameters.SigAlg, value); }
        }
        public string Signature
        {
            get { return GetParameter(Saml2Constants.Parameters.Signature); }
            set { SetParameter(Saml2Constants.Parameters.Signature, value); }
        }

        #region Private 

        public virtual string BuildRedirectUrl()
        {
            var _issuerAddress = this.IssuerAddress;
            StringBuilder strBuilder = new StringBuilder(_issuerAddress);
            bool issuerAddressHasQuery = _issuerAddress.Contains("?");
            foreach (KeyValuePair<string, string> parameter in this.Parameters)
            {
                if (parameter.Value == null)
                {
                    continue;
                }

                if (!issuerAddressHasQuery)
                {
                    strBuilder.Append('?');
                    issuerAddressHasQuery = true;
                }
                else
                {
                    strBuilder.Append('&');
                }
                strBuilder.Append(Uri.EscapeDataString(parameter.Key));
                strBuilder.Append('=');
                strBuilder.Append(parameter.Value);
            }
            return strBuilder.ToString();
        }

        private byte[] SignData(AsymmetricAlgorithm key, byte[] data, HashAlgorithmName hashAlgorithmName)
        {
            if (key is RSA)
            {
                var rsa = (RSA)key;
                return rsa.SignData(data, hashAlgorithmName, RSASignaturePadding.Pkcs1);
            }
            else if (key is DSA)
            {
                var dsa = (DSA)key;
                return dsa.CreateSignature(data);
            }
            else if (key is ECDsa)
            {
                var ecdsa = (ECDsa)key;
                return ecdsa.SignData(data, hashAlgorithmName);
            }
            throw new Saml2Exception("Signing key must be an instance of either RSA, DSA or ECDSA.");
        }

        //To construct the signature, a string consisting of the concatenation of the RelayState(if present),
        //SigAlg, and SAMLRequest(or SAMLResponse) query string parameters(each one URLencoded) is constructed
        //in one of the following ways(ordered as 'SAMLRequest=value&RelayState=value&SigAlg=value')
        private string GetQuerySignature(AsymmetricAlgorithm key, string result, HashAlgorithmName hashAlgorithmName)
        {
            // Check if the key is of a supported type. [SAMLBind] sect. 3.4.4.1 specifies this.
            if (!(key is RSA || key is DSA || key is ECDsa || key == null))
                throw new Saml2Exception("Signing key must be an instance of either RSA, DSA or ECDSA.");
            //TODO
            //if (key == null)
            //    return;

            //convert to uri to get the query string later
            Uri uri = new Uri(result);

            // Calculate the signature of the URL as described in [SAMLBind] section 3.4.4.1.            
            var signature = SignData(key, Encoding.UTF8.GetBytes(uri.Query), hashAlgorithmName);

            return HttpUtility.UrlEncode(Convert.ToBase64String(signature));
        }
        private static string GetQuerySignAlg(string signatureMethod)
        {
            if (signatureMethod == null)
                return null;

            var urlEncoded = signatureMethod.UrlEncode();
            return urlEncoded.UpperCaseUrlEncode();
        }

        private static string EncodeDeflateMessage(string request)
        {
            var encoded = request.DeflateEncode();
            var urlEncoded = encoded.UrlEncode();
            return urlEncoded.UpperCaseUrlEncode();
        }


        //[RequiresUnreferencedCode("Calls System.Xml.Serialization.XmlSerializer.XmlSerializer(System.Type)")]
        private static XmlDocument Serialize<T>(T item) where T : class
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
