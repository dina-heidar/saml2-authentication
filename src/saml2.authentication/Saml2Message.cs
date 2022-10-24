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
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Serialization;
using MetadataBuilder.Schema.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Xml;
using Saml.MetadataBuilder;
using static Saml2Core.Saml2Constants;
using Reference = System.Security.Cryptography.Xml.Reference;

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
            string authnRequestId, string relayState, string sendAssertionTo)
        {
            var idpConfiguration = GetIdpDescriptor(options.Configuration);
            var idpSingleServiceSignOnEndpoints = idpConfiguration.SingleSignOnServices;
            var issuer = GetSignOnEndpoint(idpSingleServiceSignOnEndpoints, options.AuthenticationMethod);

            NameIDType entityID = new NameIDType()
            {
                Value = options.EntityId
            };
            var authnRequest = new AuthnRequestType()
            {
                ID = authnRequestId,
                Issuer = entityID,
                Version = Saml2Constants.Version,
                ForceAuthn = options.ForceAuthn,
                ForceAuthnSpecified = true,
                IsPassive = options.IsPassive,
                IsPassiveSpecified = true,
                //new NameIDType()
                //{
                //    Format = options.NameId.Format,
                //    Value = options.EntityId,
                //    SPProvidedID = options.NameId.SpProvidedId,
                //    SPNameQualifier = options.NameId.SpNameQualifier,
                //    NameQualifier = options.NameId.NameQualifier
                //},
                NameIDPolicy = new NameIDPolicyType()
                {
                    Format = options.NameId.Format,
                    SPNameQualifier = options.NameId.SpNameQualifier,
                    AllowCreate = true,
                    AllowCreateSpecified = true
                },
                Destination =  issuer,
                //AssertionConsumerServiceIndex = options.AssertionConsumerServiceIndex,
                AssertionConsumerServiceURL = sendAssertionTo,//options.AssertionConsumerServiceUrl.AbsoluteUri,
                ProtocolBinding =  GetProtocolBinding(options.ResponseProtocolBinding),
                IssueInstant = DateTime.UtcNow,
               
            };

            //create xml
            var authnRequestXmlDoc = Serialize<AuthnRequestType>(authnRequest);

            var saml2Message = new Saml2Message()
            {
                IssuerAddress = issuer
            };
                      

            //authentication request
            //saml2Message.SamlRequest = authnRequestXmlDoc.OuterXml;           

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
                //redirect binding
                //if there is a certificate to sign the authnrequest
                if (options.SigningCertificate != null && options.AuthenticationRequestSigned)
                {
                    saml2Message.SamlRequest = (authnRequestXmlDoc.OuterXml).DeflateEncode().UrlEncode().UpperCaseUrlEncode();
                    //relay state
                    saml2Message.Relay = relayState.DeflateEncode().UrlEncode();

                    (var key, var signatureMethod, var keyName) =
                        XmlDocumentExtensions.SetSignatureAlgorithm(options.SigningCertificate);

                    //get signAlg
                    saml2Message.SigAlg = signatureMethod.UrlEncode().UpperCaseUrlEncode();//GetQuerySignAlg(signatureMethod);

                    var builder = new StringBuilder();
                    //var requestSignedUrlString = builder
                    //    .AppendFormat("{0}=", Saml2Constants.Parameters.SamlRequest)
                    //    .Append((authnRequestXmlDoc.OuterXml).DeflateEncode().UrlEncode().UpperCaseUrlEncode())
                    //    .AppendFormat("&{0}=", Saml2Constants.Parameters.RelayState)
                    //    .Append(relayState.DeflateEncode().UrlEncode())
                    //    .AppendFormat("&{0}=", Saml2Constants.Parameters.SigAlg)
                    //    .Append(signatureMethod.UrlEncode().UpperCaseUrlEncode());

                    var requestSignedUrlString = builder
                        .AppendFormat("{0}=", Saml2Constants.Parameters.SamlRequest)
                        .Append((authnRequestXmlDoc.OuterXml).DeflateEncode().UrlEncode().UpperCaseUrlEncode())
                        .AppendFormat("&{0}=", Saml2Constants.Parameters.RelayState)
                        .Append(relayState.DeflateEncode().UrlEncode())
                        .AppendFormat("&{0}=", Saml2Constants.Parameters.SigAlg)
                        .Append(signatureMethod.UrlEncode().UpperCaseUrlEncode());



                    //Uri uri = new Uri(requestSignedUrlString);
                    //var queryString = $"{Saml2Constants.Parameters.SamlRequest}={saml2Message.SamlRequest}&{Saml2Constants.Parameters.RelayState}={saml2Message.Relay}&{Saml2Constants.Parameters.SigAlg}={saml2Message.SigAlg}";//uri.Query.Remove(0, 1);

                    var signature = SignData(key, Encoding.UTF8.GetBytes(requestSignedUrlString.ToString()), 
                        options.SigningCertificateHashAlgorithmName);
                    //get signature                
                    saml2Message.Signature = HttpUtility.UrlEncode(Convert.ToBase64String(signature));

                    requestSignedUrlString.AppendFormat("&{0}=", Saml2Constants.Parameters.Signature)
                        .Append(HttpUtility.UrlEncode(Convert.ToBase64String(signature)));
                    //GetQuerySignature(options.SigningCertificate.PrivateKey,requestSignedUrlString, options.SigningCertificateHashAlgorithmName);
                    //var result = $"{Saml2Constants.Parameters.SamlRequest}={saml2Message.SamlRequest}&{Saml2Constants.Parameters.RelayState}={saml2Message.Relay}&{Saml2Constants.Parameters.SigAlg}={saml2Message.SigAlg}&{Saml2Constants.Parameters.Signature}={saml2Message.Signature}";
                    return $"{issuer}?{requestSignedUrlString}";
                }
                return issuer; // saml2Message.BuildRedirectUrl();
            }
        }
        public virtual string GetToken(ResponseType responseType, X509Certificate2 x509Certificate2)
        {
            var key = (AsymmetricAlgorithm)x509Certificate2.GetRSAPublicKey() ??
                x509Certificate2.GetECDsaPublicKey();
            return GetTokenUsingXmlReader(responseType, key);
        }
        public virtual string GetTokenUsingXmlReader(ResponseType responseType, AsymmetricAlgorithm key)
        {
            string token;
            string xmlTemplate;
            var assertion = responseType.Items[0];
            if (assertion == null)
            {
                throw new Saml2Exception("Missing assertion");
            }

            //check if its a decrypted assertion
            if (assertion.GetType() == typeof(EncryptedElementType))
            {
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
                    throw new Saml2Exception("Response signature is not valid");
                }
            }
            var samlResponseType = DeSerializeToClass<ResponseType>(samlResponseString);
            return samlResponseType;
        }
        public void CheckIfReplayAttack(string inResponseTo, string base64OriginalSamlRequestId)
        {
            string originalSamlRequestId = base64OriginalSamlRequestId.Base64Decode();

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
            get => SamlResponse != null;
        }
        public string SamlRequest
        {
            get { return GetParameter(Saml2Constants.Parameters.SamlRequest); }
            set { SetParameter(Saml2Constants.Parameters.SamlRequest, value); }
        }
        public string Relay
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
        public string SamlResponse
        {
            get { return GetParameter(Saml2Constants.Parameters.SamlResponse); }
            set { SetParameter(Saml2Constants.Parameters.SamlResponse, EncodeDeflateMessage(value)); }
        }
        public virtual StringBuilder BuildRedirectUrl()
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
            return strBuilder;
        }
        public static IDPSSODescriptor GetIdpDescriptor(EntityDescriptor configuration)
        {
            var idpConfiguration = (configuration.Items
                   .FirstOrDefault(i => i.GetType() == typeof(IDPSSODescriptor)) as IDPSSODescriptor);

            return idpConfiguration;
        }

        #region Private 

        private static bool ValidateXmlSignature(XmlDocument xmlDoc,
            bool verifySignatureOnly, EntityDescriptor configuration)
        {
            var signedXml = new SignedXml(xmlDoc);
            var signatureElement = xmlDoc.GetElementsByTagName(Saml2Constants.Parameters.Signature,
                Saml2Constants.Namespaces.DsNamespace);

            // Checking If the Response or the Assertion has been signed once and only once.
            if (signatureElement.Count != 1)
                throw new InvalidOperationException("Too many signatures!");

            signedXml.LoadXml((XmlElement)signatureElement[0]);

            // a metadata might be multiple signing certificates (Idp have this).
            // get the correct one and check it
            var x509data = signedXml.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
            var signedCertificate = (X509Certificate2)x509data.Certificates[0];
            var idpCertificates = GetIdpDescriptor(configuration).SigningCertificates;

            // validate references here!
            if ((signedXml.SignedInfo.References[0] as Reference)?.Uri != "")
                throw new InvalidOperationException("Check your references!");

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
                    return ToSymmetricKey(encryptedKey, encryptedElement.EncryptedData.EncryptionMethod.Algorithm, privateKey);
                }
            }
            throw new Saml2Exception("Unable to locate assertion decryption key.");
        }
        private SymmetricAlgorithm ToSymmetricKey(EncryptedKey encryptedKey, string hashAlgorithm,
            AsymmetricAlgorithm privateKey)
        {

            bool useOaep = encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl;

            if (encryptedKey.CipherData != null)
            {
                byte[] cipherValue = encryptedKey.CipherData.CipherValue;
                var key = GetKeyInstance(hashAlgorithm);
                key.Key = EncryptedXml.DecryptKey(cipherValue, (RSA)privateKey, useOaep);
                return key;
            }

            throw new NotImplementedException("Unable to decode CipherData of type \"CipherReference\".");
        }
        private static SymmetricAlgorithm GetKeyInstance(string hashAlgorithm)
        {
            Rijndael key = Rijndael.Create(hashAlgorithm);
            return key;
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
