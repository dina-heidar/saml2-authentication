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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Saml2Metadata;
using Saml2Metadata.Schema;
using static Saml2Authentication.Saml2Constants;

namespace Saml2Authentication
{
    internal class Saml2Message : AuthenticationProtocolMessage
    {
        #region Constructors
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
        #endregion

        #region Properties
        public bool IsSignInMessage
        {
            get => SamlResponse != null || SamlArt != null || ArtifactResponse != null;
        }
        public bool IsLogoutMessage
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
            set { SetParameter(Saml2Constants.Parameters.ArtifactResolve, value); }
        }
        public string ArtifactResponse
        {
            get { return GetParameter(Saml2Constants.Parameters.ArtifactResponse); }
            set { SetParameter(Saml2Constants.Parameters.ArtifactResponse, value); }
        }
        public Artifact Artifact { get; set; }

        #endregion

        #region Methods
        /// <summary>
        /// Creates the sign in request.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="authnRequestId">The authn request identifier.</param>
        /// <param name="relayState">State of the relay.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">
        /// The identity provider does not support 'HTTP-Artifact' binding protocol. ArtifactResolutionServices endpoint was not found.
        /// or
        /// Missing signing certificate. Either add a signing certitifcatre or change the `AuthenticationRequestSigned` to `false`.
        /// </exception>
        public string CreateSignInRequest(Saml2Options options,
            string authnRequestId, string relayState)
        {
            var idpConfiguration = GetIdpDescriptor(options.Configuration);
            var idpSingleServiceSignOnEndpoints = idpConfiguration.SingleSignOnServices;
            var destination = GetSignOnEndpoint(idpSingleServiceSignOnEndpoints, options.AuthenticationMethod,
                options.IdpSingleSignOnServiceLocationIndex.ToString());

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
                    AllowCreate = options.NameIdPolicy.AllowCreate,
                    AllowCreateSpecified = true
                },
                Destination = destination,
                AssertionConsumerServiceIndex = (options.AssertionConsumerServiceIndex != null ? options.AssertionConsumerServiceIndex.Value : (ushort)0),
                AssertionConsumerServiceIndexSpecified = options.AssertionConsumerServiceIndex.HasValue,
                AssertionConsumerServiceURL = options.AssertionConsumerServiceUrl?.AbsoluteUri,
                ProtocolBinding = GetProtocolBinding((Saml2ResponseProtocolBinding)options.ResponseProtocolBinding),
                IssueInstant = DateTime.UtcNow,
            };

            //create xml
            var authnRequestXmlDoc = Serialize<AuthnRequestType>(authnRequest);

            var saml2Message = new Saml2Message()
            {
                IssuerAddress = destination
            };

            if (options.ResponseProtocolBinding == Saml2ResponseProtocolBinding.Artifact)
            {
                if (idpConfiguration.ArtifactResolutionServices.Count() == 0)
                {
                    throw new Saml2Exception("The identity provider does not support 'HTTP-Artifact' binding protocol. ArtifactResolutionServices endpoint was not found.");
                }
            }

            //check if there is a signature certificate
            if (options.SigningCertificate == null && options.AuthenticationRequestSigned)
            {
                throw new Saml2Exception("Missing signing certificate. Either add a signing certitifcatre or change the `AuthenticationRequestSigned` to `false`.");
            }

            //if post method and needs signature then we need to ign the entire xml
            if (options.AuthenticationMethod == Saml2AuthenticationBehaviour.FormPost)
            {
                var samlRequest = authnRequestXmlDoc;
                if (options.SigningCertificate != null && options.AuthenticationRequestSigned)
                {
                    samlRequest = authnRequestXmlDoc.AddXmlSignature(options.SigningCertificate, Elements.Issuer,
                        Namespaces.Assertion, $"#{authnRequestId}");
                }
                
                saml2Message.SamlRequest = System.Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(samlRequest.OuterXml));
                saml2Message.RelayState = relayState.DeflateEncode();//.UrlEncode();

                return saml2Message.BuildFormPost();
            }
            else
            {
                //redirect binding

                saml2Message.SamlRequest = (authnRequestXmlDoc.OuterXml).DeflateEncode().UrlEncode().UpperCaseUrlEncode();
                //relay state
                saml2Message.RelayState = relayState.DeflateEncode().UrlEncode();

                //if there is a certificate to add a query signature parameter to the authnrequest
                if (options.SigningCertificate != null && options.AuthenticationRequestSigned)
                {
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

        /// <summary>
        /// Creates the logout request.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="logoutRequestId">The logout request identifier.</param>
        /// <param name="sessionIndex">Index of the session.</param>
        /// <param name="relayState">State of the relay.</param>
        /// <param name="forcedSignout">if set to <c>true</c> [forced signout].</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">
        /// The identity provider does not support 'HTTP-Artifact' binding protocol. ArtifactResolutionServices endpoint was not found.
        /// or
        /// Missing signing certificate. Either add a signing certitifcatre or change the `AuthenticationRequestSigned` to `false`.
        /// </exception>
        public string CreateLogoutRequest(Saml2Options options,
            string logoutRequestId, string sessionIndex,
            string relayState, bool forcedSignout = false)
        {
            var idpConfiguration = GetIdpDescriptor(options.Configuration);
            var idpSingleServiceSingleLogoutEndpoints = idpConfiguration.SingleLogoutServices;
            var destination = GetSingleLogoutEndpoint(idpSingleServiceSingleLogoutEndpoints, options.LogoutMethod,
                options.IdpSingleLogoutServiceLocationIndex.ToString());

            var logoutRequest = new LogoutRequestType()
            {
                ID = logoutRequestId,
                Issuer = new NameIDType()
                {
                    Value = options.EntityId
                },
                Version = Saml2Constants.Version,
                Reason = (forcedSignout == false ? Saml2Constants.Reasons.User : Saml2Constants.Reasons.Admin),
                SessionIndex = new string[] { sessionIndex },
                Destination = destination,
                IssueInstant = DateTime.UtcNow,
                Item = new NameIDType()
                {
                    Format = options.NameId?.Format,
                    NameQualifier = options.NameId?.NameQualifier,
                    SPProvidedID = options.NameId?.SpProvidedId,
                    SPNameQualifier = options.NameId?.NameQualifier,
                    Value = options.NameId.Value
                }
            };

            //create xml
            var logoutRequestXmlDoc = Serialize<LogoutRequestType>(logoutRequest);

            var saml2Message = new Saml2Message()
            {
                IssuerAddress = destination
            };

            if (options.ResponseProtocolBinding == Saml2ResponseProtocolBinding.Artifact)
            {
                if (idpConfiguration.ArtifactResolutionServices.Count() == 0)
                {
                    throw new Saml2Exception("The identity provider does not support 'HTTP-Artifact' binding protocol. ArtifactResolutionServices endpoint was not found.");
                }
            }

            //check if there is a signature certificate
            if (options.SigningCertificate == null && options.LogoutRequestSigned)
            {
                throw new Saml2Exception("Missing signing certificate. Either add a signing certitifcatre or change the `AuthenticationRequestSigned` to `false`.");
            }

            //if post method and needs signature then we need to sign the entire xml
            if (options.LogoutMethod == Saml2LogoutBehaviour.FormPost)
            {
                if (options.SigningCertificate != null && options.LogoutRequestSigned)
                {
                    var signedLogoutRequestXmlDoc = logoutRequestXmlDoc.AddXmlSignature(options.SigningCertificate, Elements.Issuer,
                        Namespaces.Assertion, $"#{logoutRequestId}");

                    saml2Message.SamlRequest = System.Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(signedLogoutRequestXmlDoc.OuterXml));
                    saml2Message.RelayState = relayState.DeflateEncode();//.UrlEncode();
                }
                return saml2Message.BuildFormPost();
            }
            else
            {
                //redirect binding
                saml2Message.SamlRequest = (logoutRequestXmlDoc.OuterXml).DeflateEncode().UrlEncode().UpperCaseUrlEncode();
                //if there is a certificate to add a query signature parameter to the logout nrequest
                if (options.SigningCertificate != null && options.LogoutRequestSigned)
                {
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

        /// <summary>
        /// Creates the artifact resolution signin request.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="authnRequestId2">The authn request id2.</param>
        /// <param name="artifact">The artifact.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">
        /// The identity provider does not support 'Artifact' binding protocol. ArtifactResolutionServices endpoint was not found.
        /// or
        /// Signature Certificate cannot be null when using HTTP-Artifact binding
        /// </exception>
        public string CreateArtifactResolutionSigninRequest(Saml2Options options,
            string authnRequestId2, string artifact)
        {
            var idpConfiguration = GetIdpDescriptor(options.Configuration);

            var artifactValue = Saml2Message.GetArtifact(artifact);
            var arsIndex = (ushort)artifactValue.EndpointIndex;

            //use the index that was in the returned parsed artifact object
            var destination = GetIdpDescriptor(options.Configuration).ArtifactResolutionServices
                .FirstOrDefault(x => x.Index == arsIndex).Location;

            var artifactResolveRequest = new ArtifactResolveType
            {
                ID = authnRequestId2,
                Issuer = new NameIDType()
                {
                    Value = options.EntityId
                },
                Version = Saml2Constants.Version,
                Artifact = artifact,
                Destination = destination,
                IssueInstant = DateTime.UtcNow
            };

            var artifactResolveRequestXmlDoc = Serialize<ArtifactResolveType>(artifactResolveRequest);

            var saml2Message = new Saml2Message()
            {
                IssuerAddress = destination
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

            //put in SOAP message here
            var artifactResolveSoapMessageRequest = new Envelope
            {
                Body = new Body
                {
                    Item = new XmlElement[]
                    {
                       SerializeToElement(signedAuthnRequestXmlDoc)
                   }
                }
            };

            var envelopeXmlDoc = Serialize(artifactResolveSoapMessageRequest);

            saml2Message.ArtifactResolve = envelopeXmlDoc.OuterXml;
            return saml2Message.ArtifactResolve;
        }

        /// <summary>
        /// Gets the token.
        /// </summary>
        /// <param name="responseType">Type of the response.</param>
        /// <param name="encryptingCertificate2">The encrypting certificate2.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Unable to find encrypting certificate RSA private key</exception>

        public virtual string GetToken(ResponseType responseType, X509Certificate2 encryptingCertificate2 = null)
        {
            if (encryptingCertificate2 != null)
            {
                var key = (AsymmetricAlgorithm)encryptingCertificate2.GetRSAPrivateKey();

                if (key == null)
                {
                    throw new Saml2Exception("Unable to find encrypting certificate RSA private key");
                }
                return GetTokenUsingXmlReader(responseType, key);
            }
            return GetTokenUsingXmlReader(responseType);
        }

        /// <summary>
        /// Gets the token using XML reader.
        /// </summary>
        /// <param name="responseType">Type of the response.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">
        /// Missing assertion
        /// or
        /// Unable to find encrypting certificate
        /// or
        /// Unable to parse the decrypted assertion.
        /// </exception>
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
                    throw new Saml2Exception("Unable to find encrypting certificate");
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

        /// <summary>
        /// Gets the assertion.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Assertion signature is not valid</exception>
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

                if (!ValidateXmlSignature(Message.SamlAssertion, doc, options.VerifySignatureOnly, options.Configuration))
                {
                    throw new Saml2Exception("Assertion signature is not valid");
                }
            }
            return DeSerializeToClass<AssertionType>(token);
        }

        /// <summary>
        /// Gets the saml response token.
        /// </summary>
        /// <param name="responseType">Type of the response.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Response signature is not valid.</exception>
        public Saml2ParsedResponseType GetSamlResponseToken(
            string responseType, Saml2Options options)
        {
            var rawSamlResponse = DecodeSamlResponseFromBase64EncodedString();
            var doc = new XmlDocument
            {
                XmlResolver = null,
                PreserveWhitespace = true
            };

            doc.LoadXml(rawSamlResponse);

            if (options.RequireMessageSigned)
            {
                if (!ValidateXmlSignature(Message.SamlResponse, doc, options.VerifySignatureOnly, options.Configuration))
                {
                    throw new Saml2Exception("Response signature is not valid.");
                }
            }

            var response = DeSerializeToClass<ResponseType>(rawSamlResponse, responseType, Saml2Constants.Namespaces.Protocol, false);
            return new Saml2ParsedResponseType(
                response,
                rawSamlResponse);
        }

        /// <summary>
        /// Gets the artifact response token.
        /// </summary>
        /// <param name="envelope">The envelope.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Response signature is not valid.</exception>
        public Saml2ParsedResponseType GetArtifactResponseToken(string envelope, Saml2Options options)
        {
            var reponseEnvelope = DeSerializeToClass<Envelope>(envelope);

            var artifactResponseElement = (XmlElement)reponseEnvelope.Body.Item[0];

            var artifactResponseType = DeSerializeToClass<ArtifactResponseType>(artifactResponseElement.OuterXml);
            var samlResponseElement = artifactResponseType.Any;

            var doc = new XmlDocument
            {
                XmlResolver = null,
                PreserveWhitespace = true
            };

            doc.LoadXml(samlResponseElement.OuterXml);

            if (options.RequireMessageSigned)
            {
                if (!ValidateXmlSignature(Message.SamlResponse, doc, options.VerifySignatureOnly, options.Configuration))
                {
                    throw new Saml2Exception("Response signature is not valid.");
                }
            }
            var samlResponseType = DeSerializeToClass<ResponseType>(samlResponseElement.OuterXml);
            return new Saml2ParsedResponseType(
                samlResponseType,
                envelope);
        }

        /// <summary>
        /// Checks if replay attack.
        /// </summary>
        /// <param name="inResponseTo">The in response to.</param>
        /// <param name="inResponseToCookieValue">The in response to cookie value.</param>
        /// <exception cref="Saml2Authentication.Saml2Exception">
        /// Empty protocol message id is not allowed.
        /// or
        /// Replay attack.
        /// </exception>
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

        /// <summary>
        /// Checks the status.
        /// </summary>
        /// <param name="responseToken">The response token.</param>
        /// <exception cref="Saml2Authentication.Saml2Exception"></exception>
        public void CheckStatus(ResponseType responseToken)
        {
            var status = responseToken.Status.StatusCode;
            if (status.Value != Saml2Constants.StatusCodes.Success)
            {
                //TODO write exception values as switch
                throw new Saml2Exception(status.Value);
            }
        }

        /// <summary>
        /// Builds a URL using the current IssuerAddress and the parameters that have been set.
        /// </summary>
        /// <returns>
        /// UrlEncoded string.
        /// </returns>
        /// <remarks>
        /// Each parameter &lt;Key, Value&gt; is first transformed using <see cref="M:System.Uri.EscapeDataString(System.String)" />.
        /// </remarks>
        public override string BuildRedirectUrl()
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

        /// <summary>
        /// Builds a form post using the current IssuerAddress and the parameters that have been set.
        /// </summary>
        /// <returns>
        /// html with head set to 'Title', body containing a hiden from with action = IssuerAddress.
        /// </returns>
        public override string BuildFormPost()
        {
            var _issuerAddress = this.IssuerAddress;

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append("<?xml version =\"1.0\" encoding =\"utf-8\"?>\r\n <!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\r\n\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\r\n<head>\r\n <title>Saml2.Authentication</title>\r\n </head>\r\n <body onload=\"document.forms[0].submit()\">\r\n <noscript><prop><strong>Note:</strong> Since your browser does not support JavaScript, you must press the Continue button once to proceed.</prop></noscript>\r\n");
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
        #endregion

        #region Public Static 
        /// <summary>
        /// Gets the idp descriptor.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        /// <returns></returns>
        public static IDPSSODescriptor GetIdpDescriptor(EntityDescriptor configuration)
        {
            var idpConfiguration = (configuration.ObjectItems
                   .FirstOrDefault(i => i.GetType() == typeof(IDPSSODescriptor)) as IDPSSODescriptor);

            return idpConfiguration;
        }

        /// <summary>
        /// Gets the artifact.
        /// </summary>
        /// <param name="parameter">The parameter.</param>
        /// <returns></returns>
        public static Artifact GetArtifact(string parameter)
        {
            if (string.IsNullOrEmpty(parameter))
                throw LogHelper.LogArgumentNullException(nameof(parameter));

            var artifact = ArtifactExtensions.GetParsedArtifact(parameter);

            return artifact;
        }

        /// <summary>
        /// Validates the artifact.
        /// </summary>
        /// <param name="artifactString">The artifact string.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        public static bool ValidateArtifact(string artifactString, Saml2Options options)
        {
            var idpDescriptor = GetIdpDescriptor(options.Configuration);

            var ars = idpDescriptor.ArtifactResolutionServices.Select(a => (ushort)a.Index).ToArray();
            var validIssuers = options.ValidIssuers.Prepend(options.Configuration.EntityID).ToArray();

            return ArtifactExtensions.IsValid(artifactString, ars, validIssuers);
        }
        #endregion

        #region Private 
        /// <summary>
        /// Decodes the SamlResponse, which is base64 encoded
        /// </summary>
        /// <returns>The raw Saml response</returns>
        private string DecodeSamlResponseFromBase64EncodedString()
        {
            if (SamlResponse.Contains("%"))
            {
                SamlResponse = HttpUtility.UrlDecode(SamlResponse);
            }

            var bytes = Convert.FromBase64String(SamlResponse);
            var samlResponseString = Encoding.UTF8.GetString(bytes);
            return samlResponseString;
        }

        /// <summary>
        /// Gets the requested authn context.
        /// </summary>
        /// <param name="requestedAuthnContext">The requested authn context.</param>
        /// <returns></returns>
        private static RequestedAuthnContextType GetRequestedAuthnContext(RequestedAuthenticationContext requestedAuthnContext)
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

        /// <summary>
        /// Validates the XML signature.
        /// </summary>
        /// <param name="messageType">Type of the message.</param>
        /// <param name="xmlDoc">The XML document.</param>
        /// <param name="verifySignatureOnly">if set to <c>true</c> [verify signature only].</param>
        /// <param name="configuration">The configuration.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Too many signatures!</exception>
        private static bool ValidateXmlSignature(string messageType, XmlDocument xmlDoc,
            bool verifySignatureOnly, EntityDescriptor configuration)
        {
            var signedXml = new SignedXml(xmlDoc);
            var signatureElement = xmlDoc.GetElementsByTagName(Saml2Constants.Parameters.Signature,
                Saml2Constants.Namespaces.DsNamespace);

            // Checking if the response or the assertion has
            // been signed once and only once.
            if (signatureElement.Count > 1)
                throw new Saml2Exception($"The {messageType} has too many signatures.");

            if (signatureElement.Count == 0)
                throw new Saml2Exception($"The {messageType} is not signed.");

            signedXml.LoadXml((XmlElement)signatureElement[0]);

            // a metadata might be multiple signing certificates (Idp have this).
            // get the correct one and check it
            var x509data = signedXml.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
            var signedCertificate = (X509Certificate2)x509data.Certificates[0];
            var idpCertificates = GetIdpDescriptor(configuration).SigningCertificates;

            //compare the idp metadata signing cert with the token signature
            //if `verifySignatureOnly` = `false` then it'll do the chain verification to make sure the certificate is valid.
            return signedXml.CheckSignature(GetIdpCertificate(idpCertificates, signedCertificate.SerialNumber),
                verifySignatureOnly);
        }

        /// <summary>
        /// Extracts the session key.
        /// </summary>
        /// <param name="encryptedElement">The encrypted element.</param>
        /// <param name="privateKey">The private key.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Unable to locate assertion decryption key.</exception>
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

        /// <summary>
        /// Converts to symmetrickey.
        /// </summary>
        /// <param name="encryptedKey">The encrypted key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Unable to decode CipherData of type \"CipherReference\".</exception>
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

        /// <summary>
        /// Gets the key instance.
        /// </summary>
        /// <returns></returns>
        private static SymmetricAlgorithm GetKeyInstance()
        {
            var sessionKey = Aes.Create();
            return sessionKey;
        }

        /// <summary>
        /// Gets the idp certificate.
        /// </summary>
        /// <param name="x509Certificate2s">The X509 certificate2s.</param>
        /// <param name="serialNumber">The serial number.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">No matching certificate found. Assertion is not from known Idp.</exception>
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

        /// <summary>
        /// Signs the data.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="data">The data.</param>
        /// <param name="hashAlgorithmName">Name of the hash algorithm.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Signing key must be an instance of either RSA, DSA or ECDSA.</exception>
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


#pragma warning disable CS1570 // XML comment has badly formed XML
        /// <summary>
        /// Gets the query signature.
        /// To construct the signature, a string consisting of the concatenation of the RelayState(if present),
        /// SigAlg, and SAMLRequest(or SAMLResponse) query string parameters(each one URLencoded) is constructed
        /// in one of the following ways(ordered as <cods>SAMLRequest=value&RelayState=value&SigAlg=value</cods>)
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="query">The query.</param>
        /// <param name="hashAlgorithmName">Name of the hash algorithm.</param>
        /// <returns></returns>
        /// <exception cref="Saml2Authentication.Saml2Exception">Signing key must be an instance of either RSA, DSA or ECDSA.</exception>
        private string GetQuerySignature(AsymmetricAlgorithm key, string query, HashAlgorithmName hashAlgorithmName)
#pragma warning restore CS1570 // XML comment has badly formed XML
        {
            // Check if the key is of a supported type. [SAMLBind] sect. 3.4.4.1 specifies this.
            if (!(key is RSA || key is DSA || key is ECDsa || key == null))
                throw new Saml2Exception("Signing key must be an instance of either RSA, DSA or ECDSA.");

            var uri = new Uri(query);
            var queryString = uri.Query.Remove(0, 1);

            // Calculate the signature of the URL as described in [SAMLBind] section 3.4.4.1.            
            var signature = SignData(key, Encoding.UTF8.GetBytes(queryString), hashAlgorithmName);

            return HttpUtility.UrlEncode(Convert.ToBase64String(signature));
        }

        /// <summary>
        /// Gets the query sign alg.
        /// </summary>
        /// <param name="signatureMethod">The signature method.</param>
        /// <returns></returns>
        private static string GetQuerySignAlg(string signatureMethod)
        {
            if (signatureMethod == null)
                return null;

            var urlEncoded = signatureMethod.UrlEncode();
            return urlEncoded.UpperCaseUrlEncode();
        }

        /// <summary>
        /// Encodes the deflate message.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        private static string EncodeDeflateMessage(string request)
        {
            var encoded = request.DeflateEncode();
            var urlEncoded = encoded.UrlEncode();
            return urlEncoded.UpperCaseUrlEncode();
        }

        /// <summary>
        /// Serializes to element.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="item">The item.</param>
        /// <returns></returns>
        private static XmlElement SerializeToElement<T>(T item) where T : class
        {
            string xmlTemplate = string.Empty;
            XmlDocument doc = Serialize<T>(item);
            XmlElement element = doc.DocumentElement;
            return element;
        }

        /// <summary>
        /// Serializes the specified item.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="item">The item.</param>
        /// <returns></returns>
        //[RequiresUnreferencedCode("Calls System.Xml.Serialization.XmlSerializer.XmlSerializer(Type)")] 
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

        /// <summary>
        /// Des the serialize to class.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="xmlString">The XML string.</param>
        /// <returns></returns>
        //[RequiresUnreferencedCode("Calls System.Xml.Serialization.XmlSerializer.XmlSerializer(Type)")]
        private static T DeSerializeToClass<T>(string xmlString) where T : class
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

        /// <summary>
        /// Des the serialize to class.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="xmlString">The XML string.</param>
        /// <param name="elementName">Name of the element.</param>
        /// <param name="namespaceString">The namespace string.</param>
        /// <param name="isNullable">if set to <c>true</c> [is nullable].</param>
        /// <returns></returns>
        //[RequiresUnreferencedCode("Calls System.Xml.Serialization.XmlSerializer.XmlSerializer(Type, XmlRootAttribute)")]
        private static T DeSerializeToClass<T>(string xmlString,
            string elementName = null, string namespaceString = null, bool isNullable = false) where T : class
        {
            var xmlRootAttribute = new XmlRootAttribute
            {
                ElementName = elementName,
                Namespace = namespaceString,
                IsNullable = isNullable
            };

            var xmlSerializer = new XmlSerializer(typeof(T), xmlRootAttribute);

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

        /// <summary>
        /// Builds the artifact.
        /// </summary>
        /// <param name="sourceIdValue">The source identifier value.</param>
        /// <param name="endpointIndexValue">The endpoint index value.</param>
        /// <returns></returns>
        private string BuildArtifact(string sourceIdValue, short endpointIndexValue)
        {
            if (string.IsNullOrEmpty(sourceIdValue))
                throw LogHelper.LogArgumentNullException(nameof(sourceIdValue));

            var artifactString = ArtifactExtensions.CreateArtifact(sourceIdValue, endpointIndexValue);

            return artifactString;
        }

        /// <summary>
        /// Gets the protocol binding.
        /// </summary>
        /// <param name="responseProtocolBinding">The response protocol binding.</param>
        /// <returns></returns>
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

        /// <summary>
        /// Gets the sign on endpoint.
        /// </summary>
        /// <param name="signOnEndpoints">The sign on endpoints.</param>
        /// <param name="method">The method.</param>
        /// <param name="idpSsoEndpointLocation">The idp sso endpoint location.</param>
        /// <returns></returns>
        private static string GetSignOnEndpoint(Endpoint[] signOnEndpoints, Saml2AuthenticationBehaviour method,
            string idpSsoEndpointLocation)
        {
            if (method == Saml2AuthenticationBehaviour.RedirectGet)
            {
                if (string.IsNullOrEmpty(idpSsoEndpointLocation))
                {
                    return signOnEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Redirect).Location;
                }
                else
                {
                    return signOnEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Redirect
                    && s.Location == idpSsoEndpointLocation).Location;
                }
            }
            else
            {
                if (string.IsNullOrEmpty(idpSsoEndpointLocation))
                {
                    return signOnEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Post).Location;
                }
                return signOnEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Post
                 && s.Location == idpSsoEndpointLocation).Location;
            }
        }

        /// <summary>
        /// Gets the single logout endpoint.
        /// </summary>
        /// <param name="singleLogoutEndpoints">The single logout endpoints.</param>
        /// <param name="method">The method.</param>
        /// <param name="idpSloEndpointLocation">The idp slo endpoint location.</param>
        /// <returns></returns>
        private static string GetSingleLogoutEndpoint(Endpoint[] singleLogoutEndpoints, Saml2LogoutBehaviour method,
           string idpSloEndpointLocation)
        {
            if (method == Saml2LogoutBehaviour.RedirectGet)
            {
                if (string.IsNullOrEmpty(idpSloEndpointLocation))
                {
                    return singleLogoutEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Redirect).Location;
                }
                else
                {
                    return singleLogoutEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Redirect
                    && s.Location == idpSloEndpointLocation).Location;
                }
            }
            else
            {
                if (string.IsNullOrEmpty(idpSloEndpointLocation))
                {
                    return singleLogoutEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Post).Location;
                }
                return singleLogoutEndpoints.FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Post
                 && s.Location == idpSloEndpointLocation).Location;
            }
        }
        #endregion
    }
}
