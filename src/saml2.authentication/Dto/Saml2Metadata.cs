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
using System.Security.Cryptography.X509Certificates;
using Saml2Metadata;

namespace Saml2Authentication
{
    public class Saml2MetadataXml
    {
        /// <summary>
        /// <para><b>Optional</b><br/>
        /// The expiration time of the metadata.<br/>
        /// Example: 2028-01-21T18:12:29.287Z
        /// </para>
        /// </summary>
        /// <value>
        /// The valid until value.
        /// </value>        
        /// <example>2028-01-21T18:12:29.287Z</example>
        public DateTime ValidUntil { get; set; }
        /// <summary>
        /// <para><b>Optional</b><br/>
        /// The maximum length of time in seconds a consumer should cache the metadata.<br/>       
        /// </para>
        /// </summary>
        /// <value>
        /// The duration of the cache in seconds.
        /// </value>
        /// <example>360000</example>
        public string CacheDuration { get; set; }
        /// <summary>
        /// <para><b>Optional</b><br/> 
        /// A document-unique identifier 
        /// for the element, typically used as a reference point when signing. <br/>
        /// Example: _35D0C44A-52CE-4D2F-BE06-AE5F00C30AA7
        /// </para>
        /// </summary>
        /// <value>
        /// The a document-unique identifier.
        /// </value>
        /// <example>35D0C44A-52CE-4D2F-BE06-AE5F00C30AA7</example>
        public string Id { get; set; }
        /// <summary>
        /// <para><b>Optional</b><br/> 
        /// Used to identifying the organization 
        /// responsible for the SAML entity, it possible 
        /// to include details such as organization’s name, 
        /// display name, URL.
        /// </para>
        /// </summary>
        /// <value>
        /// The organization.
        /// </value>
        public Organization Organization { get; set; }
        // <summary>
        /// <para><b>Optional</b><br/> 
        /// used to provide various kind of information about 
        /// a contact person such as individuals’ name,
        /// email address and phone numbers.
        /// </para>
        /// </summary>
        /// <value>
        /// The contact persons.
        /// </value>
        public ContactPerson ContactPersons { get; set; }
        /// <summary>
        /// Gets or sets the UI information displayed 
        /// during sign in on Idp.
        /// </summary>
        /// <value>
        /// The UI information.
        /// </value>
        public UiInfo UiInfo { get; set; }
        /// <summary>
        /// Gets or sets the attribute consuming service.
        /// </summary>
        /// <value>
        /// The attribute consuming service.
        /// </value>
        public AttributeConsumingService AttributeConsumingService { get; set; }
        /// <summary>
        /// Signs the entire metadata.
        /// </summary>
        /// <value>
        /// The signature.
        /// </value>
        public X509Certificate2 Signature { get; set; }
        internal string EntityID { get; set; }
        internal string NameIdFormat { get; set; }
        internal bool AuthnRequestsSigned { get; set; }
        internal bool WantAssertionsSigned { get; set; }
        internal IndexedEndpoint AssertionConsumerService { get; set; }
        internal Endpoint SingleLogoutServiceEndpoint { get; set; }
        internal EncryptingCertificate EncryptingCertificate { get; set; } = new EncryptingCertificate();
        internal X509Certificate2 SigningCertificate { get; set; }
    }
}
