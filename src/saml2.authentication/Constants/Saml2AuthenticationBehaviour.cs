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

namespace Saml2Core
{
    /// <summary>
    /// Lists the different authentication methods used to
    /// redirect the user agent to the identity provider.
    /// </summary>
    public enum Saml2AuthenticationBehaviour
    {
        /// <summary>
        /// Emits a 302 response to redirect the user agent to
        /// the Idp using a GET request.
        /// </summary>
        RedirectGet = 0,

        /// <summary>
        /// Emits an HTML form to redirect the user agent to
        /// the Idp using a POST request.
        /// </summary>
        FormPost = 1,

        /// <summary>
        /// Creates an artifact and send it the Idp artifact endpoint
        /// using GET request.
        /// </summary>
        Artifact = 3
    }
}
