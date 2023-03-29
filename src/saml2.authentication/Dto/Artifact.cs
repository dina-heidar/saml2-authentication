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
    internal class Artifact
    {
        /// <summary>
        /// Gets or sets the type code value.
        /// Type of the artifact. This is always 0x0004
        /// </summary>
        /// <value>
        /// The type code value.
        /// </value>
        public short TypeCodeValue { get; set; }
        public string TypeCodeValueString { get; set; }
        /// <summary>
        /// Gets or sets the index of the endpoint.
        /// The issuer's artifact Resolution Service endpoint 
        /// where the artifact should be resolved
        /// </summary>
        /// <value>
        /// The index of the endpoint.
        /// </value>
        public short? EndpointIndex { get; set; }
        public string EndpointIndexString { get; set; }
        /// <summary>
        /// Gets or sets the source code identifier. 
        /// Represents the entity ID of the provider who created 
        /// this artifact. The entity ID is hashed using SHA-1, 
        /// ensuring that it's always 20 bytes in length
        /// </summary>
        /// <value>
        /// The source code identifier.
        /// </value>
        public byte[] SourceCodeId { get; set; }
        public string SourceCodeIdString { get; set; }
        /// <summary>
        /// Gets or sets the message handler.
        /// A cryptographically random value that identifies this specific artifact
        /// </summary>
        /// <value>
        /// The message handler.
        /// </value>
        public byte[] MessageHandler { get; set; }
        public string MessageHandlerString { get; set; }

    }
}
