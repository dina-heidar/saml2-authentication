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

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Saml2Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public class MessageReceivedContext : RemoteAuthenticationContext<Saml2Options>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="properties"></param>
        public MessageReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            Saml2Options options,
            AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        /// <summary>
        /// The <see cref="Saml2Message"/> received on this request.
        /// </summary>
        internal Saml2Message ProtocolMessage { get; set; } = default!;
    }
}
