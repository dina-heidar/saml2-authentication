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

using System.ComponentModel;
using System.Xml.Linq;
using Microsoft.Extensions.Hosting;

namespace Saml2Core
{
    public class Saml2Constants
    {
        public const string Version = "2.0";
        public static class Parameters
        {
            public const string SamlRequest = "SAMLRequest";
            public const string RelayState = "RelayState";
            public const string SigAlg = "SigAlg";
            public const string Signature = "Signature";
            public const string SamlResponse = "SAMLResponse";
        }
        public static class NameIDFormats
        {
            /// <summary>
            /// The email. Indicates that the content of the 
            /// element is in the form of an email address
            /// </summary>
            public const string Email = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
            /// <summary>
            /// The persistent. Indicates that the content of the element is a persistent 
            /// opaque identifier for a principal that is specific to  an identity provider 
            /// and a service provider or affiliation of service providers.
            /// </summary>
            public const string Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
            /// <summary>
            /// The transient. Indicates that the content of the element is an identifier with 
            /// transient semantics and SHOULD be treated as an opaque and temporary value by the relying party
            /// </summary>
            public const string Transient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
            /// <summary>
            /// The unspecified. The interpretation of the content of the element is left to 
            /// individual implementations.
            /// </summary>
            public const string Unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
            /// <summary>
            /// The encrypted. Indicates a request that the resulting identifier be encrypted.
            /// </summary>
            public const string Encrypted = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
            /// <summary>
            /// The entity identifier.Indicates that the content of the element is the identifier 
            /// of an entity that provides SAML-based services (such as a SAML authority, requester, or responder) 
            /// or is a participant in SAML profiles(such as a service provider supporting the browser SSO profile).
            /// Such an identifier can be used in the [Issuer] element to identify the issuer of a SAML request, 
            /// response, or assertion, or within the [NameID] element to make assertions about system 
            /// entities that can issue SAML requests, responses, and assertions.It can also be used in 
            /// other elements and attributes whose purpose is to identify a system entity in various protocol exchanges.
            /// </summary>
            public const string EntityIdentifier = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
            /// <summary>
            /// The kerberos principal name. Indicates that the content of the element is in the 
            /// form of a Kerberos principal name using the format name[/ instance] @REALM.
            /// </summary>
            public const string KerberosPrincipalName = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
            /// <summary>
            /// The subject name.Indicates that the content of the element is in the form 
            /// specified for the contents of the [ds:X509SubjectName] element in the XML 
            /// Signature Recommendation[XMLSig].         
            /// </summary>
            public const string SubjectName = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
            /// <summary>
            /// The windows domain qualified name.Indicates that the content of the element is a 
            /// Windows domain qualified name. A Windows domain qualified user name is a string 
            /// of the form "DomainName\UserName". The domain name and "\" separator MAY be omitted.
            /// </summary>
            public const string WindowsDomainQualifiedName = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
        }
        public static class ResponseTypes
        {
            public const string AuthnResponse = "Response";
            public const string LogoutResponse = "LogoutResponse";
        }
        public static class Saml2ClaimTypes
        {
            public const string Namespace = "http://saml2Core/";
            public const string SessionIndex = $"{Namespace}sid";
        }
        public static class ProtocolBindings
        {
            public const string HTTP_Redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
            public const string HTTP_Post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
            public const string HTTP_Artifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
        }
        public static class Tracing
        {
            public static readonly string Basic = Saml2Core.Tracing.TraceNames.Basic;
            public static readonly string Stores = Saml2Core.Tracing.TraceNames.Store;
            public static readonly string Cache = Saml2Core.Tracing.TraceNames.Cache;
            public static readonly string Validation = Saml2Core.Tracing.TraceNames.Validation;
            public static readonly string Services = Saml2Core.Tracing.TraceNames.Services;
            public static readonly string ServiceVersion = Saml2Core.Tracing.ServiceVersion;
        }
    }
}
