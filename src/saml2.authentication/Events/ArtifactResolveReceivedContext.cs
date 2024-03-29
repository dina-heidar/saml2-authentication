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

using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Saml2Authentication
{

    /// <summary>
    /// This Context can be used to be informed when an 'Artifact' is received over the Saml2 protocol.
    /// </summary>
    public class ArtifactResolveReceivedContext : RemoteAuthenticationContext<Saml2Options>
    {
        /// <summary>
        /// Creates a <see cref="ArtifactResolveReceivedContext"/>
        /// </summary>
        public ArtifactResolveReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            Saml2Options options,
            AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        /// <summary>
        /// Gets or sets the protocol message.
        /// </summary>
        /// <value>
        /// The protocol message.
        /// </value>
        internal Saml2Message ProtocolMessage { get; set; } = default!;

        /// <summary>
        /// Gets or sets the <see cref="Saml2SecurityTokenHandler" /> that was received in the artifact resolution response, if any.
        /// </summary>
        /// <value>
        /// The saml2 security token handler.
        /// </value>
        public Saml2SecurityTokenHandler saml2SecurityTokenHandler { get; set; }

        /// <summary>
        /// The request that will be sent to the artifact resolution endpoint.
        /// </summary>
        internal Saml2Message ArtifactResolutionRequest { get; set; }

        /// <summary>
        /// The configured communication channel to the identity provider 
        /// for use when making custom requests to the artificat resolution endpoint.
        /// </summary>
        public HttpClient Backchannel { get; internal set; } = default!;


        /// <summary>
        /// Gets or sets the artifact resolution response.
        /// </summary>
        /// <value>
        /// The artifact resolution response.
        /// </value>
        internal Saml2Message ArtifactResolutionResponse { get; set; }


        /// <summary>
        /// Gets a value indicating whether [handled artifact resolve redemption].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [handled artifact resolve redemption]; otherwise, <c>false</c>.
        /// </value>
        public bool HandledArtifactResolveRedemption => ArtifactResolutionResponse != null;


        /// <summary>
        /// Handles the saml artifact resolution response.
        /// </summary>
        public void HandleSamlArtifactResolutionResponse()
        {
            ArtifactResolutionResponse = new Saml2Message();
        }

        /// <summary>
        /// Handles the saml artifact resolution response.
        /// </summary>
        /// <param name="artifactResponse">The artifact response.</param>
        public void HandleSamlArtifactResolutionResponse(string artifactResponse)
        {
            ArtifactResolutionResponse = new Saml2Message() { ArtifactResponse = artifactResponse };
        }

        internal void HandleSamlArtifactResolutionResponse(Saml2Message samlArtResponse)
        {
            ArtifactResolutionResponse = samlArtResponse;
        }
    }

}
