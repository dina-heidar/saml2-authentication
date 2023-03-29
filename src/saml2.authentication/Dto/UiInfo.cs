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

namespace Saml2Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public class UiInfo
    {
        /// <summary>
        /// Gets or sets the display name.
        /// </summary>
        /// <value>
        /// The display name.
        /// </value>
        public string DisplayName { get; set; }
        /// <summary>
        /// Gets or sets the language.
        /// </summary>
        /// <value>
        /// The language.
        /// </value>
        public string Language { get; set; }

        /// <summary>
        /// Gets or sets the description.
        /// </summary>
        /// <value>
        /// The description.
        /// </value>
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets the information URL.
        /// </summary>
        /// <value>
        /// The information URL.
        /// </value>
        public Uri InformationURL { get; set; }

        /// <summary>
        /// Gets or sets the privacy statement URL.
        /// </summary>
        /// <value>
        /// The privacy statement URL.
        /// </value>
        public Uri PrivacyStatementURL { get; set; }

        /// <summary>
        /// Gets or sets the height.
        /// </summary>
        /// <value>
        /// The rendered height of the logo measured in pixels.
        /// </value>
        public string LogoHeight { get; set; }

        /// <summary>
        /// Gets or sets the width.
        /// </summary>
        /// <value>
        /// The rendered width of the logo measured in pixels.
        /// </value>
        public string LogoWidth { get; set; }
        /// <summary>
        /// Gets or sets the value as a Url.
        /// </summary>
        /// <value>
        /// The value.
        /// </value>
        public Uri LogoUriValue { get; set; }
        /// <summary>
        /// Gets or sets the values.
        /// </summary>
        /// <value>
        /// The values.
        /// </value>
        public string[] KeywordValues { get; set; }
    }
}
