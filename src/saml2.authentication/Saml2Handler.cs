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
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using MetadataBuilder.Schema.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Saml.MetadataBuilder;
using static Saml2Core.Saml2Constants;

namespace Saml2Core
{
    internal class Saml2Handler : RemoteAuthenticationHandler<Saml2Options>,
        IAuthenticationSignOutHandler
    {
        private readonly ISaml2Service _saml2Service;
        private readonly ILogger<Saml2Handler> _logger;
        private EntityDescriptor? _configuration;
        protected HttpClient Backchannel => Options.Backchannel;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2Handler" /> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        /// <param name="encoder">The encoder.</param>
        /// <param name="clock">The clock.</param>
        /// <param name="saml2Service">The saml2 service.</param>
        public Saml2Handler(
            IOptionsMonitor<Saml2Options> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock,
            ISaml2Service saml2Service
            ) : base(options, loggerFactory, encoder, clock)
        {
            _logger = loggerFactory.CreateLogger<Saml2Handler>();
            _saml2Service = saml2Service;

            Options.AssertionConsumerServiceUrl = (Options.AssertionConsumerServiceUrl == null ?
                new Uri(new Uri(CurrentUri), Options.CallbackPath) : Options.AssertionConsumerServiceUrl);
        }
        protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {

            throw new NotImplementedException();
        }
        Task IAuthenticationSignOutHandler.SignOutAsync(AuthenticationProperties properties)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// The handler calls methods on the events which give the 
        /// application control at certain points where processing 
        /// is occurring. If it is not provided a default instance 
        /// is supplied which does nothing when the methods are called.
        /// </summary>
        protected new Saml2Events Events
        {
            get { return (Saml2Events)base.Events; }
            set { base.Events = value; }
        }
        /// <summary>
        /// Creates the events asynchronous.
        /// </summary>
        /// <returns></returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new Saml2Events());

        /// <summary>
        /// Handles the request asynchronous.
        /// </summary>
        /// <returns></returns>
        public override Task<bool> HandleRequestAsync()
        {
            if (Options.RemoteSignOutPath.HasValue && Options.RemoteSignOutPath == Request.Path)
            {
                // we've received a remote sign-out request
                return HandleRemoteSignOutAsync();
            }
            else if (Options.SignOutPath.HasValue && Options.SignOutPath == Request.Path)
            {
                return HandleSignOutCallbackAsync();
            }
            return base.HandleRequestAsync();
        }

        /// <summary>
        /// Override this method to deal with 401 challenge concerns, if an authentication scheme in question
        /// deals an authentication interaction as part of it's request flow. (like adding a response header, or
        /// changing the 401 result to 302 of a login page or external sign-in location.)
        /// </summary>
        /// <param name="properties"></param>
        /// <returns>
        /// A Task.
        /// </returns>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Logger.EnteringOpenIdAuthenticationHandlerHandleUnauthorizedAsync(GetType().FullName!);

            // order for local RedirectUri
            // 1. challenge.Properties.RedirectUri
            // 2. CurrentUri if RedirectUri is not set)
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = OriginalPathBase + Options.CallbackPath;
            }

            Logger.PostAuthenticationLocalRedirect(properties.RedirectUri);

            if (_configuration == null && Options.ConfigurationManager != null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                Options.Configuration = _configuration;
            }

            //prepare            
            //get the assertion service Url
            var saml2ResponseUrl = BuildRedirectUri(Options.CallbackPath);

            //generate a nonce of random bytes and retain it in a browser cookie
            //and encode this nonce and other information in the authentication properties
            //'properties.Dictionary[correlationKey] = correlationId;'
            //this will later be passed in a state query string parameter to the
            //identity provider. The identity provider will return this value right
            //back to your application after authenticating the user.         
            GenerateCorrelationId(properties);
            string relayState = Options.StateDataFormat.Protect(properties);

            //get the identity provider url - where the authn request needs to be sent to
            var idpConfiguration = _configuration.Items
                    .FirstOrDefault(i => i.GetType() == typeof(IDPSSODescriptor)) as IDPSSODescriptor;
           
            //maybe add an option to select a specific one in case there are many?
            var idpSingleServiceSignOnUrls = idpConfiguration.SingleSignOnServices;

            //TODO - Create saml cookie session to check against then delete it
            //According to the SAML specification, the SAML response returned by the IdP
            //should have an InResponseTo field that matches the authn request ID. This ties the SAML
            //response to the authn request. The authn request ID is saved in the SAML session
            //state so it can be checked against the InResponseTo.
           

            //get the string outer xml
            //add relay state as query string
            var request = new StringBuilder();

            //if authnRequest is redirect
            if (Options.AuthenticationMethod == Saml2AuthenticationBehaviour.RedirectGet)
            {
                //get the identity provider http-redirect sso endpoint
                var idpSingleServiceGetSignOnUrl = idpSingleServiceSignOnUrls
                    .FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Redirect).Location;

                var assertionConsumerServiceUrl = new Uri(new Uri(CurrentUri), Options.CallbackPath).AbsoluteUri;

                

                //string authnRequestIdOld = "id" + Guid.NewGuid().ToString("N");
                var authnRequestOld = _saml2Service.CreateAuthnRequest(Options,
                    authnRequestIdOld, relayState, assertionConsumerServiceUrlOld, idpSingleServiceGetSignOnUrl);
                //call idp
                Response.Redirect(authnRequestOld);

            //    //create authnrequest xml object
            //    //var authnRequestXmlDoc = await _saml2Service.CreateAuthnRequestAsync(saml2ResponseUrl, idpSingleServiceGetSignOnUrl);

            //    var result = authnRequestXmlDoc.OuterXml;

            //    //convert to base64
            //    request.AddMessageParameter(result, null);

            //    //add relay state as base64
            //    request.AddRelayState(result, relayState);

            //    if (Options.SigningCertificate != null && Options.AuthenticationRequestSigned)
            //    {
            //        (var key, var signatureMethod, var keyName) =
            //            XmlDocumentExtensions.SetSignatureAlgorithm(Options.SigningCertificate);

            //        //add signAlg
            //        request.AddSignAlg(result, signatureMethod);

            //        //add signature to query string
            //        request = _saml2Service.AppendQuerySignature(request, key);
            //    }
            //    //TODO
            //    var test = $"{idpSingleServiceGetSignOnUrl}?{request}";
            //    //send to idp as redirect
            //    Response.Redirect($"{idpSingleServiceGetSignOnUrl}?{request}");
            //}
            ////it is a post method
            //else
            //{
            //    //get the identity provider http-post sso endpoint
            //    var idpSingleServicePostSignOnUrl = idpSingleServiceSignOnUrls
            //        .FirstOrDefault(s => s.Binding == ProtocolBindings.HTTP_Post).Location;

            //    //create authnrequest xml object
            //    var authnRequestXmlDoc = await _saml2Service.CreateAuthnRequestAsync(saml2ResponseUrl, idpSingleServicePostSignOnUrl);

            //    if (Options.SigningCertificate != null && Options.AuthenticationRequestSigned)
            //    {
            //        //sign xml document
            //        authnRequestXmlDoc.AddXmlSignature(Options.SigningCertificate);
            //    }

            //    var authnRequestEncoded = authnRequestXmlDoc.OuterXml.EncodeDeflateMessage();

            //    var parameters = new Dictionary<string, string>
            //    {
            //        { Saml2Constants.Parameters.SamlRequest, authnRequestEncoded }
            //    };

            //    var content = _saml2Service.BuildFormPost(idpSingleServicePostSignOnUrl, parameters);
            //    var buffer = Encoding.UTF8.GetBytes(content);

            //    Response.ContentLength = buffer.Length;
            //    Response.ContentType = "text/html;charset=UTF-8";

            //    // Emit Cache-Control=no-cache to prevent client caching.             
            //    Response.Headers.Add("Cache-Control", "no-cache, no-store");
            //    Response.Headers.Add("Pragma","no-cache");
            //    Response.Headers.Add("Expires", "Thu, 01 Jan 1970 00:00:00 GMT");

            //    await Response.Body.WriteAsync(buffer, 0, buffer.Length);
            //    return;
            }
        }


        protected virtual Task<bool> HandleSignOutCallbackAsync()
        {
            return Task.FromResult(true);
        }

        protected virtual async Task<bool> HandleRemoteSignOutAsync()
        {
            if (Request.Method != HttpMethods.Post)
                return false;

            var form = await Request.ReadFormAsync();

            var relayState = form[Saml2Constants.Parameters.RelayState].ToString()?.DeflateDecompress();

            var authenticationProperties = Options.StateDataFormat.Unprotect(relayState);

            // check if it is an idp initiated logout request or an sp intiated logout request 
            // idp initated logout request. 
            // the idp sends this out when a user wants to logout from a session in another app.
            // it'll log them out of all other active sessions for other applications.
            if (await _saml2Service.IsLogoutRequestAsync(Context.Request))
            {
                try
                {
                    // sign user out from saml2 cookie
                    await Context.SignOutAsync(Options.SignOutScheme, authenticationProperties);
                    Response.DeleteAllRequestIdCookies(Context.Request, Options.Saml2CoreCookieName);

                    // must send a logout response 
                    // get the sid and create it?
                    // get the inresponseto value and ID
                    var logoutReponse = await _saml2Service.GetLogoutResponseAsync();
                    //send the logout reponse to idp
                    //TODO change this!

                    //maybe send a new httpclient request??
                    //check and see if it'll come back from idp with anything
                    //check if this can be done via backchannel
                    var content = "hwllo";
                    var buffer = Encoding.UTF8.GetBytes(content);

                    Response.ContentLength = buffer.Length;
                    Response.ContentType = "text/html;charset=UTF-8";

                    // Emit Cache-Control=no-cache to prevent client caching.

                    //var t= await Response.Body.WriteAsync(buffer);
                    Response.Redirect(logoutReponse.ID);

                    //go back to app main page
                    var redirectUrll = !string.IsNullOrEmpty(authenticationProperties.RedirectUri) ?
                        authenticationProperties.RedirectUri : Options.DefaultRedirectUrl.ToString();

                    Response.Redirect(redirectUrll, true);
                    return true;
                }
                catch
                {
                    //TODO
                }

                return false;
            }

            // sp initated logout request.
            // this is the response recieved from the
            // idp as a result of the sp intiated logout request.
            var response = form[Saml2Constants.Parameters.SamlResponse];
            //var relayState = form[Saml2Constants.Parameters.RelayState].ToString()?.DeflateDecompress();

            //var authenticationProperties = Options.StateDataFormat.Unprotect(relayState);

            string base64EncodedSamlResponse = response;
            ResponseType idpSamlResponseToken = await _saml2Service.GetLogoutResponseAsync();

            IRequestCookieCollection cookies = Request.Cookies;
            string signoutSamlRequestId = cookies[cookies.Keys.FirstOrDefault(key =>
            key.StartsWith(Options.Saml2CoreCookieLifetime + ".Signout"))];

            await _saml2Service.CheckIfReplayAttackAsync();
            await _saml2Service.CheckStatusAsync();

            //check to see if successfully logged out from both app and idp
            if (Context.User.Identity.IsAuthenticated)
                return false;

            await Context.SignOutAsync(Options.SignOutScheme, authenticationProperties);
            Response.DeleteAllRequestIdCookies(Context.Request, Options.Saml2CoreCookieName);

            var redirectUrl = !string.IsNullOrEmpty(authenticationProperties.RedirectUri) ?
                authenticationProperties.RedirectUri : Options.DefaultRedirectUrl.ToString();

            Response.Redirect(redirectUrl, true);
            return true;
        }
    }
}

