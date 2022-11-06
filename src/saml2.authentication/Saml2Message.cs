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
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Serialization;
using MetadataBuilder.Schema.Metadata;
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
        public Saml2Message(IEnumerable<KeyValuePair<string, string[]>> parameters)
        {
            if (parameters == null)
            {
                //TODO
                //LogHelper.LogWarning(FormatInvariant(LogMessages.IDX22000, LogHelper.MarkAsNonPII(nameof(parameters))));
                return;
            }

            foreach (KeyValuePair<string, string[]> keyValue in parameters)
            {
                foreach (string strValue in keyValue.Value)
                {
                    SetParameter(keyValue.Key, strValue);
                }
            }
        }
        public string CreateSignInRequest(Saml2Options options,
            string authnRequestId, string relayState)
        {
            var idpConfiguration = GetIdpDescriptor(options.Configuration);
            var idpSingleServiceSignOnEndpoints = idpConfiguration.SingleSignOnServices;
            var issuer = GetSignOnEndpoint(idpSingleServiceSignOnEndpoints, options.AuthenticationMethod);

            var authnRequest = new AuthnRequestType()
            {
                ID = authnRequestId,
                Issuer = new NameIDType()
                {
                    Value = options.EntityId
                },
                Version = Saml2Constants.Version,
                ForceAuthn = options.ForceAuthn,
                ForceAuthnSpecified = true,
                IsPassive = options.IsPassive,
                IsPassiveSpecified = true,
                RequestedAuthnContext = GetRequestedAuthnContext(options.RequestedAuthnContext),
                NameIDPolicy = new NameIDPolicyType()
                {
                    Format = options.NameIdPolicy.Format,
                    SPNameQualifier = options.NameIdPolicy.SpNameQualifier,
                    AllowCreate = true,
                    AllowCreateSpecified = true
                },
                Destination = issuer,
                AssertionConsumerServiceIndex = (options.AssertionConsumerServiceIndex != null ? options.AssertionConsumerServiceIndex.Value : (ushort)0),
                AssertionConsumerServiceIndexSpecified = options.AssertionConsumerServiceIndex.HasValue,
                AssertionConsumerServiceURL = options.AssertionConsumerServiceUrl?.AbsoluteUri,
                ProtocolBinding = (options.ResponseProtocolBinding != null ? GetProtocolBinding((Saml2ResponseProtocolBinding)options.ResponseProtocolBinding) : null),
                IssueInstant = DateTime.UtcNow,
            };

            //create xml
            var authnRequestXmlDoc = Serialize<AuthnRequestType>(authnRequest);

            var saml2Message = new Saml2Message()
            {
                IssuerAddress = issuer
            };

            if (options.ResponseProtocolBinding == Saml2ResponseProtocolBinding.Artifact)
            {               
                if (idpConfiguration.ArtifactResolutionServices.Count() == 0)
                {
                    throw new Saml2Exception("The identity provider does not support 'HTTP-Artifact' binding protocol. ArtifactResolutionServices endpoint was not found.");
                }
            }

            //if post method and needs signature then we need to ign the xml itself 
            if (options.AuthenticationMethod == Saml2AuthenticationBehaviour.FormPost)
            {
                if (options.SigningCertificate != null && options.AuthenticationRequestSigned)
                {
                    var signedAuthnRequestXmlDoc = authnRequestXmlDoc.AddXmlSignature(options.SigningCertificate, Elements.Issuer,
                        Namespaces.Assertion, $"#{authnRequestId}");

                    saml2Message.SamlRequest = System.Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(signedAuthnRequestXmlDoc.OuterXml));
                    saml2Message.RelayState = relayState.DeflateEncode();//.UrlEncode();
                }
                return saml2Message.BuildFormPost();
            }
            else
            {
                //redirect binding
                //if there is a certificate to sign the authnrequest
                if (options.SigningCertificate != null && options.AuthenticationRequestSigned)
                {
                    saml2Message.SamlRequest = (authnRequestXmlDoc.OuterXml).DeflateEncode().UrlEncode().UpperCaseUrlEncode();
                    //relay state
                    saml2Message.RelayState = relayState.DeflateEncode().UrlEncode();

                    (var key, var signatureMethod, var keyName) =
                        XmlDocumentExtensions.SetSignatureAlgorithm(options.SigningCertificate);

                    //get signAlg
                    saml2Message.SigAlg = GetQuerySignAlg(signatureMethod);

                    //get signature
                    saml2Message.Signature = GetQuerySignature(key, saml2Message.BuildRedirectUrl(), options.SigningCertificateHashAlgorithmName);
                }
                return saml2Message.BuildRedirectUrl();
            }
        }

        public string CreateArtifactResolutionRequest(Saml2Options options, string authnRequestId2, string artifact)
        {
            var idpConfiguration = GetIdpDescriptor(options.Configuration);
            var idpSingleServiceArtifactEndpoints = idpConfiguration.ArtifactResolutionServices;
            var issuer = GetSignOnEndpoint(idpSingleServiceArtifactEndpoints, options.AuthenticationMethod);

            var artifactResolveRequest = new ArtifactResolveType
            {
                ID = authnRequestId2,
                Issuer = new NameIDType()
                {
                    Value = options.EntityId
                },
                Version = Saml2Constants.Version,
                Artifact = artifact,
                Destination = issuer,
                IssueInstant = DateTime.UtcNow       
            };

            var artifactResolveRequestXmlDoc = Serialize<ArtifactResolveType>(artifactResolveRequest);

            var saml2Message = new Saml2Message()
            {
                IssuerAddress = issuer
            };

            if (options.ResponseProtocolBinding == Saml2ResponseProtocolBinding.Artifact)
            {
                if (idpConfiguration.ArtifactResolutionServices.Count() == 0)
                {
                    throw new Saml2Exception("The identity provider does not support 'Artifact' binding protocol. ArtifactResolutionServices endpoint was not found.");
                }
            }

            //artifact resolution MUST be signed
            if (options.SigningCertificate == null)
            {
                throw new Saml2Exception("Signature Certificate cannot be null when using HTTP-Artifact binding");
            }
                var signedAuthnRequestXmlDoc = artifactResolveRequestXmlDoc.AddXmlSignature(options.SigningCertificate, Elements.Issuer,
                    Namespaces.Assertion, $"#{authnRequestId2}");

                saml2Message.ArtifactResolve = System.Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(signedAuthnRequestXmlDoc.OuterXml));
            return saml2Message.ArtifactResolve;
        } 
        public virtual string GetToken(ResponseType responseType, X509Certificate2 encryptingCertificate2 = null)
        {
            if (encryptingCertificate2 != null)
            {
                var key = (AsymmetricAlgorithm)encryptingCertificate2.GetRSAPrivateKey();
                return GetTokenUsingXmlReader(responseType, key);
            }
            return GetTokenUsingXmlReader(responseType);
        }
        public virtual string GetTokenUsingXmlReader(ResponseType responseType, AsymmetricAlgorithm key = null)
        {
            string token;
            var assertion = responseType.Items[0];
            if (assertion == null)
            {
                throw new Saml2Exception("Missing assertion");
            }

            //check if it is a decrypted assertion and 
            //if the encryption certificate was provided
            if (assertion.GetType() == typeof(EncryptedElementType))
            {
                if (key == null)
                {
                    throw new Saml2Exception("Unable to find encryption certificate RSA private key");
                }

                var encryptedElement = (EncryptedElementType)assertion;
                SymmetricAlgorithm sessionKey;

                if (encryptedElement.EncryptedData.EncryptionMethod != null)
                {
                    sessionKey = ExtractSessionKey(encryptedElement, key);

                    var encryptedXml = new EncryptedXml();

                    var xmlDoc = Serialize<EncryptedDataType>(encryptedElement.EncryptedData);

                    var xmlNodeList = xmlDoc.GetElementsByTagName("EncryptedData");
                    var encryptedData = new EncryptedData();
                    encryptedData.LoadXml((XmlElement)xmlNodeList[0]);

                    byte[] plaintext = encryptedXml.DecryptData(encryptedData, sessionKey);
                    token = Encoding.UTF8.GetString(plaintext);
                    return token;
                }
            }
            else
            {
                var xmlDoc = Serialize<AssertionType>((AssertionType)assertion);
                string request = xmlDoc.OuterXml;
                return request;
            }
            throw new Saml2Exception("Unable to parse the decrypted assertion.");
        }
        public AssertionType GetAssertion(string token, Saml2Options options)
        {
            if (options.WantAssertionsSigned)
            {
                var doc = new XmlDocument
                {
                    XmlResolver = null,
                    PreserveWhitespace = true
                };
                doc.LoadXml(token);

                if (!ValidateXmlSignature(doc, options.VerifySignatureOnly, options.Configuration))
                {
                    throw new Saml2Exception("Assertion signature is not valid");
                }
            }
            return DeSerializeToClass<AssertionType>(token);
        }
        public ResponseType GetSamlResponseToken(string base64EncodedSamlResponse, Saml2Options options)
        {
            var doc = new XmlDocument
            {
                XmlResolver = null,
                PreserveWhitespace = true
            };

            if (base64EncodedSamlResponse.Contains("%"))
            {
                base64EncodedSamlResponse = HttpUtility.UrlDecode(base64EncodedSamlResponse);
            }

            byte[] bytes = Convert.FromBase64String(base64EncodedSamlResponse);
            string samlResponseString = Encoding.UTF8.GetString(bytes);
            doc.LoadXml(samlResponseString);

            if (options.RequireMessageSigned)
            {
                if (!ValidateXmlSignature(doc, options.VerifySignatureOnly, options.Configuration))
                {
                    throw new Saml2Exception("Response signature is not valid.");
                }
            }
            var samlResponseType = DeSerializeToClass<ResponseType>(samlResponseString);
            return samlResponseType;
        }
        public ArtifactResponseType GetArtifactResponseToken(string base64EncodedSamlResponse, Saml2Options options)
        {
            var doc = new XmlDocument
            {
                XmlResolver = null,
                PreserveWhitespace = true
            };

            if (base64EncodedSamlResponse.Contains("%"))
            {
                base64EncodedSamlResponse = HttpUtility.UrlDecode(base64EncodedSamlResponse);
            }

            byte[] bytes = Convert.FromBase64String(base64EncodedSamlResponse);
            string artifactResponseString = Encoding.UTF8.GetString(bytes);
            doc.LoadXml(artifactResponseString);

            if (options.RequireMessageSigned)
            {
                if (!ValidateXmlSignature(doc, options.VerifySignatureOnly, options.Configuration))
                {
                    throw new Saml2Exception("Artifact Response signature is not valid.");
                }
            }
            var artifactResponseType= DeSerializeToClass<ArtifactResponseType>(artifactResponseString);
            return artifactResponseType;
        }
        public void CheckIfReplayAttack(string inResponseTo, string inResponseToCookieValue)
        {
            string originalSamlRequestId = inResponseToCookieValue.Base64Decode();

            if (string.IsNullOrEmpty(originalSamlRequestId) || string.IsNullOrEmpty(inResponseTo))
            {
                throw new Saml2Exception("Empty protocol message id is not allowed.");
            }

            if (!inResponseTo.Equals(originalSamlRequestId, StringComparison.OrdinalIgnoreCase))
            {
                throw new Saml2Exception("Replay attack.");
            }
        }
        public void CheckStatus(ResponseType responseToken)
        {
            var status = responseToken.Status.StatusCode;
            if (status.Value != Saml2Constants.StatusCodes.Success)
            {
                //TODO write exception values as switch
                throw new Saml2Exception(status.Value);
            }
        }
        public bool IsSignInMessage
        {
            get => SamlResponse != null || SamlArt != null || ArtifactResponse != null;
        }
        public string SamlRequest
        {
            get { return GetParameter(Saml2Constants.Parameters.SamlRequest); }
            set { SetParameter(Saml2Constants.Parameters.SamlRequest, value); }
        }
        public string RelayState
        {
            get { return GetParameter(Saml2Constants.Parameters.RelayState); }
            set { SetParameter(Saml2Constants.Parameters.RelayState, value); }
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
        public string SamlArt
        {
            get { return GetParameter(Saml2Constants.Parameters.SamlArt); }
            set { SetParameter(Saml2Constants.Parameters.SamlArt, value); }
        }
        public string SamlResponse
        {
            get { return GetParameter(Saml2Constants.Parameters.SamlResponse); }
            set { SetParameter(Saml2Constants.Parameters.SamlResponse, EncodeDeflateMessage(value)); }
        }
        public string ArtifactResolve
        {
            get { return GetParameter(Saml2Constants.Parameters.ArtifactResolve); }
            set { SetParameter(Saml2Constants.Parameters.ArtifactResolve, EncodeDeflateMessage(value)); }
        }
        public string ArtifactResponse
        {
            get { return GetParameter(Saml2Constants.Parameters.ArtifactResponse); }
            set { SetParameter(Saml2Constants.Parameters.ArtifactResponse, EncodeDeflateMessage(value)); }
        }
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
                strBuilder.AppendFormat("{0}=", parameter.Key);
                strBuilder.Append(parameter.Value);
            }
            return strBuilder.ToString();
        }
        public virtual string BuildFormPost()
        {
            var _issuerAddress = this.IssuerAddress;

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append("<?xml version =\"1.0\" encoding =\"utf-8\"?>\r\n <!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\r\n\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\r\n<head>\r\n <title>SAML2Core</title>\r\n </head>\r\n <body onload=\"document.forms[0].submit()\">\r\n <noscript><prop><strong>Note:</strong> Since your browser does not support JavaScript, you must press the Continue button once to proceed.</prop></noscript>\r\n");
            stringBuilder.AppendFormat("<html><head><body><form method='post' name='hiddenform' action='{0}'><div>", _issuerAddress);

            foreach (KeyValuePair<string, string> parameter in this.Parameters)
            {
                stringBuilder.AppendFormat("<input type='hidden' id='{0}' name='{0}' value='{1}' />", parameter.Key, parameter.Value);
            }
            stringBuilder.Append("<noscript><div><input type =\"submit\" value =\"Continue\"/></div ></noscript>");
            stringBuilder.Append("</div></form></body></html>");
            stringBuilder.Append(Script);
            return stringBuilder.ToString();
        }
        public static IDPSSODescriptor GetIdpDescriptor(EntityDescriptor configuration)
        {
            var idpConfiguration = (configuration.Items
                   .FirstOrDefault(i => i.GetType() == typeof(IDPSSODescriptor)) as IDPSSODescriptor);

            return idpConfiguration;
        }

        #region Private 

        private static RequestedAuthnContextType GetRequestedAuthnContext(RequestedAuthnContext requestedAuthnContext)
        {
            if (requestedAuthnContext != null)
            {
                Enum.TryParse<AuthnContextComparisonType>(requestedAuthnContext.ComparisonType, out AuthnContextComparisonType comparisonType);
                Enum.TryParse<ItemsChoiceType7>(requestedAuthnContext.AuthnContextClassRef, out ItemsChoiceType7 itemsChoiceType7);

                return new RequestedAuthnContextType
                {
                    Comparison = comparisonType,
                    ComparisonSpecified = true,
                    ItemsElementName = new ItemsChoiceType7[] { itemsChoiceType7 },
                    Items = requestedAuthnContext.AuthnContextRefTypes
                };
            }
            return null;
        }
        private static bool ValidateXmlSignature(XmlDocument xmlDoc,
            bool verifySignatureOnly, EntityDescriptor configuration)
        {
            var signedXml = new SignedXml(xmlDoc);
            var signatureElement = xmlDoc.GetElementsByTagName(Saml2Constants.Parameters.Signature,
                Saml2Constants.Namespaces.DsNamespace);

            // Checking if the response or the assertion has been signed once and only once.
            if (signatureElement.Count != 1)
                throw new Saml2Exception("Too many signatures!");

            signedXml.LoadXml((XmlElement)signatureElement[0]);

            // a metadata might be multiple signing certificates (Idp have this).
            // get the correct one and check it
            var x509data = signedXml.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
            var signedCertificate = (X509Certificate2)x509data.Certificates[0];
            var idpCertificates = GetIdpDescriptor(configuration).SigningCertificates;

            return signedXml.CheckSignature(GetIdpCertificate(idpCertificates, signedCertificate.SerialNumber),
                verifySignatureOnly);
        }
        private SymmetricAlgorithm ExtractSessionKey(EncryptedElementType encryptedElement,
            AsymmetricAlgorithm privateKey)
        {
            if (encryptedElement.EncryptedData != null)
            {
                if (encryptedElement.EncryptedData.KeyInfo.Items[0] != null)
                {
                    XmlElement encryptedKeyElement = (XmlElement)encryptedElement.EncryptedData.KeyInfo.Items[0];
                    var encryptedKey = new EncryptedKey();
                    encryptedKey.LoadXml(encryptedKeyElement);
                    return ToSymmetricKey(encryptedKey, privateKey);
                }
            }
            throw new Saml2Exception("Unable to locate assertion decryption key.");
        }
        private SymmetricAlgorithm ToSymmetricKey(EncryptedKey encryptedKey,
            AsymmetricAlgorithm privateKey)
        {
            bool useOaep = encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl;

            if (encryptedKey.CipherData != null)
            {
                byte[] cipherValue = encryptedKey.CipherData.CipherValue;
                var key = GetKeyInstance();

                key.Key = EncryptedXml.DecryptKey(cipherValue, (RSA)privateKey, useOaep);
                return key;
            }
            throw new Saml2Exception("Unable to decode CipherData of type \"CipherReference\".");
        }
        private static SymmetricAlgorithm GetKeyInstance()
        {
            var sessionKey = Aes.Create();
            return sessionKey;
        }
        private static X509Certificate2 GetIdpCertificate(X509Certificate2[] x509Certificate2s,
            string serialNumber)
        {
            X509Certificate2 cert = x509Certificate2s.Where(c => c.SerialNumber == serialNumber).FirstOrDefault();
            if (cert == null)
            {
                throw new Exception("No matching certificate found. Assertion is not from known Idp.");
            }
            return cert;
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
        private string GetQuerySignature(AsymmetricAlgorithm key, string query, HashAlgorithmName hashAlgorithmName)
        {
            // Check if the key is of a supported type. [SAMLBind] sect. 3.4.4.1 specifies this.
            if (!(key is RSA || key is DSA || key is ECDsa || key == null))
                throw new Saml2Exception("Signing key must be an instance of either RSA, DSA or ECDSA.");
            //TODO
            //if (key == null)
            //    return;

            var uri = new Uri(query);
            var queryString = uri.Query.Remove(0, 1);

            // Calculate the signature of the URL as described in [SAMLBind] section 3.4.4.1.            
            var signature = SignData(key, Encoding.UTF8.GetBytes(queryString), hashAlgorithmName);

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
        private T DeSerializeToClass<T>(string xmlString) where T : class
        {
            var xmlSerializer = new XmlSerializer(typeof(T));
            var safeSettings = new XmlReaderSettings
            {
                XmlResolver = null,
                DtdProcessing = DtdProcessing.Prohibit,
                ValidationType = ValidationType.None
            };

            using (var reader = XmlReader.Create(new StringReader(xmlString), safeSettings))
            {
                return ((T)xmlSerializer.Deserialize(reader));
            }
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
