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

namespace Saml2Authentication
{
    public class NameIdPolicy
    {
        /// <summary>
        /// [Optional] Specifies the URI reference corresponding to a name identifier 
        /// format defined in this or another specification(see Section 8.3 for examples). 
        /// The additional value of urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted 
        /// is defined specifically for use within this attribute to indicate a request 
        /// that the resulting identifier be encrypted.
        /// </summary>
        public string Format { get; set; }
        /// <summary>
        /// [Optional] Specifies that the assertion subject's identifier be returned (or created) 
        /// in the namespace of a service provider other than the requester, or in the namespace 
        /// of an affiliation group of service providers.See for example the definition of 
        /// urn:oasis:names:tc:SAML:2.0:nameidformat:persistent in Section 8.3.7.
        /// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 3.4.1.1
        /// </summary>
        public string SpNameQualifier { get; set; }
        /// <summary>
        /// [Optional] A Boolean value used to indicate whether the identity provider is allowed, 
        /// in the course of fulfilling the request, to create a new identifier to represent the
        /// principal.Defaults to "false". When "false", the requester constrains the identity 
        /// provider to only issue an assertion to it if an acceptable identifier for the principal 
        /// has already been established.Note that this does not prevent the identity provider from 
        /// creating such identifiers outside the context of this specific request (for example, 
        /// in advance for a large number of principals).
        /// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 3.4.1.1
        /// </summary>
        public bool AllowCreate { get; set; }
    }
}
