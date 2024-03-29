﻿// Copyright (c) 2019 Dina Heidar
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
    public class RequestedAttribute
    {
        /// <summary>
        /// Gets or sets the attribute value.
        /// </summary>
        /// <value>
        /// The attribute value.
        /// </value>
        public string[] AttributeValue { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>
        /// The name.
        /// </value>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the name format.
        /// </summary>
        /// <value>
        /// The name format.
        /// </value>
        public string NameFormat { get; set; }

        /// <summary>
        /// Gets or sets the name of the friendly.
        /// </summary>
        /// <value>
        /// The name of the friendly.
        /// </value>
        public string FriendlyName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance is required field.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is required field; otherwise, <c>false</c>.
        /// </value>
        public bool IsRequiredField { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance is required field specified.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is required field specified; otherwise, <c>false</c>.
        /// </value>
        public bool IsRequiredFieldSpecified { get; set; } = true;
    }
}
