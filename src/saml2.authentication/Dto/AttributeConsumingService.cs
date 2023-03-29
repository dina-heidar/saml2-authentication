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
    public class AttributeConsumingService
    {
        /// <summary>
        /// Gets or sets the service names.
        /// </summary>
        /// <value>
        /// The service names.
        /// </value>
        public string ServiceNames { get; set; }

        /// <summary>
        /// Gets or sets the service descriptions.
        /// </summary>
        /// <value>
        /// The service descriptions.
        /// </value>
        public string ServiceDescriptions { get; set; }

        /// <summary>
        /// Gets or sets the language.
        /// </summary>
        /// <value>
        /// The language.
        /// </value>
        public string Language { get; set; } = "en-US";

        /// <summary>
        /// Gets or sets the requested attributes.
        /// Requested Attributes in Service Provider (SP) metadata are used by the Identity Provider (IdP) 
        /// to make attribute release decisions. An IdP may also use it in conjunction with 
        /// other user interface elements to construct the user attribute release consent form. 
        /// </summary>
        /// <value>
        /// The requested attributes.
        /// </value>
        public RequestedAttribute[] RequestedAttributes { get; set; }
    }
}
