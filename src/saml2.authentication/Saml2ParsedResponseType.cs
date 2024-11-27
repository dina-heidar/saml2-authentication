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

using Saml2Metadata.Schema;

namespace Saml2Authentication
{
    /// <summary>
    /// Contains the parsed response and the raw response.
    /// </summary>
    public class Saml2ParsedResponseType
    {
        /// <summary>
        /// Constructs a new instance of <see cref="Saml2ParsedResponseType"/>.
        /// </summary>
        /// <param name="response">The parsed response</param>
        /// <param name="rawResponse">The raw response</param>
        public Saml2ParsedResponseType(ResponseType response, string rawResponse)
        {
            Response = response;
            RawResponse = rawResponse;
        }

        /// <summary>
        /// The parsed response.
        /// </summary>
        public ResponseType Response { get; }

        /// <summary>
        /// The raw input, this is needed for signature validation.
        /// </summary>
        public string RawResponse { get; }
    }
}
