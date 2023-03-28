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
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace Saml2Core
{
    public class Saml2Events : RemoteAuthenticationEvents
    {
        //        /// <summary>
        //        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        //        /// </summary>
        //        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        //public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;
        public Func<ArtifactResolveReceivedContext, Task> OnArtifactResolveReceived { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
        /// </summary>
        //public Func<RedirectContext, Task> OnRedirectToIdentityProvider { get; set; } = context => Task.CompletedTask;

        //        /// <summary>
        //        /// Invoked when a wsignoutcleanup request is received at the RemoteSignOutPath endpoint.
        //        /// </summary>
        //        public Func<RemoteSignOutContext, Task> OnRemoteSignOut { get; set; } = context => Task.CompletedTask;

        //        /// <summary>
        //        /// Invoked with the security token that has been extracted from the protocol message.
        //        /// </summary>
        //        public Func<SecurityTokenReceivedContext, Task> OnSecurityTokenReceived { get; set; } = context => Task.CompletedTask;

        //        /// <summary>
        //        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        //        /// </summary>
        //        public Func<SecurityTokenValidatedContext, Task> OnSecurityTokenValidated { get; set; } = context => Task.CompletedTask;

        //        /// <summary>
        //        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        //        /// </summary>
        //        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        //public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

        public virtual Task ArtifactResolveReceived(ArtifactResolveReceivedContext context) => OnArtifactResolveReceived(context);

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.        
        /// Invoked before redirecting to the identity provider to authenticate. This can be used 
        /// to set ProtocolMessage.State that will be persisted through the authentication process. 
        /// The ProtocolMessage can also be used to add or customize
        /// parameters sent to the identity provider.
        /// </summary>     
       // public virtual Task RedirectToIdentityProvider(RedirectContext context) => OnRedirectToIdentityProvider(context);

        //        /// <summary>
        //        /// Invoked when a wsignoutcleanup request is received at the RemoteSignOutPath endpoint.
        //        /// </summary>
        //        public virtual Task RemoteSignOut(RemoteSignOutContext context) => OnRemoteSignOut(context);

        //        /// <summary>
        //        /// Invoked with the security token that has been extracted from the protocol message.
        //        /// </summary>
        //        public virtual Task SecurityTokenReceived(SecurityTokenReceivedContext context) => OnSecurityTokenReceived(context);

        //        /// <summary>
        //        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        //        /// </summary>
        //        public virtual Task SecurityTokenValidated(SecurityTokenValidatedContext context) => OnSecurityTokenValidated(context);
    }
}
