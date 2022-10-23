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
using System.Security.Claims;
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
        private const string CorrelationProperty = ".xsrf";
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
        }
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            Saml2Message saml2Message = null;
            AuthenticationProperties properties = null;

            // assumption: if the ContentType is "application/x-www-form-urlencoded"
            // it should be safe to read as it is small.
            if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync(Context.RequestAborted);

                // ToArray handles the StringValues.IsNullOrEmpty case.
                // We assume non-empty Value does not contain null elements.
#pragma warning disable CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
                saml2Message = new Saml2Message(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value.ToArray())));
#pragma warning restore CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
            }

            if (saml2Message == null || !saml2Message.IsSignInMessage)
            {
                if (Options.SkipUnrecognizedRequests)
                {
                    // Not for us?
                    return HandleRequestResult.SkipHandler();
                }
                return HandleRequestResults.NoMessage;
            }

            try
            {
                //get relay
                var relayState = saml2Message.Relay.DeflateDecompress();

                //get authentication properties
                properties = Options.StateDataFormat.Unprotect(relayState);

                if (properties == null)
                {
                    if (!Options.AllowUnsolicitedLogins)
                    {
                        return HandleRequestResults.UnsolicitedLoginsNotAllowed;
                    }
                    //TODO do stuff to handle the Idp unsolicited login
                    //make the lifetime exp short 
                }
                else
                {
                    // Extract the user state from properties and reset.
                    properties.Items.TryGetValue(Saml2Defaults.UserstatePropertiesKey, out var userState);
                    saml2Message.Relay = userState;
                }

                var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options, properties)
                {
                    ProtocolMessage = saml2Message
                };
                await Events.MessageReceived(messageReceivedContext);

                if (messageReceivedContext.Result != null)
                {
                    if (messageReceivedContext.Result.Handled)
                    {
                        Logger.MessageReceivedContextHandledResponse();
                    }
                    else if (messageReceivedContext.Result.Skipped)
                    {
                        Logger.MessageReceivedContextSkipped();
                    }
                    return messageReceivedContext.Result;
                }
                saml2Message = messageReceivedContext.ProtocolMessage;
                properties = messageReceivedContext.Properties!; // Provides a new instance if not set.

                // If state did flow from the challenge then validate it. 
                if (properties.Items.TryGetValue(CorrelationProperty, out string correlationId)
                    && !ValidateCorrelationId(properties))
                {
                    return HandleRequestResult.Fail(Properties.Resources.CorrelationFailure, properties);
                }

                if (saml2Message.SamlResponse == null)
                {
                    Logger.SignInWithoutWResult();
                    return HandleRequestResult.Fail(Properties.Resources.SignInMessageSamlResponseIsMissing, properties);
                }

                //since this is a solicited login (sent from challenge)
                // we must compare the incoming 'InResponseTo' what we have in the cookie
                var requestCookies = Request.Cookies;
                var inResponseTo = requestCookies[requestCookies.Keys.FirstOrDefault(key => key.StartsWith(Saml2Constants.InResponseToId))];

                //read saml response and vaidate signature if needed
                var responseToken = saml2Message.GetSamlResponseToken(saml2Message.SamlResponse, Options);

                //validate it is not a replay attack
                saml2Message.CheckIfReplayAttack(responseToken.InResponseTo, inResponseTo);
                saml2Message.CheckStatus(responseToken);

                var token = saml2Message.GetToken(responseToken, Options.SigningCertificate);

                var assertion = saml2Message.GetAssertion(token, Options);

                var session = new AuthnStatementType();

                if (assertion.Items.Any(x => x.GetType() == typeof(AuthnStatementType)))
                {
                    session = (AuthnStatementType)assertion.Items.FirstOrDefault(x => x.GetType() == typeof(AuthnStatementType));
                }

                if (assertion.Subject.Items.Any(x => x.GetType() == typeof(NameIDType)))
                {
                    var nameIdType = (NameIDType)assertion.Subject.Items.FirstOrDefault(x => x.GetType() == typeof(NameIDType));
                    Options.NameId = new NameId
                    {
                        NameQualifier = nameIdType.NameQualifier,
                        SpNameQualifier = nameIdType.SPNameQualifier,
                        Format = nameIdType.Format,
                        SpProvidedId = nameIdType.SPProvidedID,
                        Value = nameIdType.Value
                    };
                }

                if (_configuration == null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                }

                var idpSigningCertificates = Saml2Message.GetIdpDescriptor(Options.Configuration).SigningCertificates;
                var idpSigningKeys = new List<SecurityKey>();
                foreach (var cert in idpSigningCertificates)
                {
                    idpSigningKeys.Add(new X509SecurityKey(cert));
                }

                var tvp = Options.TokenValidationParameters.Clone();
                var validator = Options.Saml2SecurityTokenHandler;
                ClaimsPrincipal principal = null;
                SecurityToken parsedToken = null;

                var issuers = new[] { responseToken.Issuer.Value };
                tvp.ValidateIssuerSigningKey = Options.WantAssertionsSigned;
                tvp.ValidateTokenReplay = !Options.IsPassive;
                tvp.ValidateIssuer = true;
                tvp.ValidateAudience = true;
                tvp.ValidIssuers = (tvp.ValidIssuers == null ? issuers : tvp.ValidIssuers.Concat(issuers));
                tvp.IssuerSigningKeys = (tvp.IssuerSigningKeys == null ? idpSigningKeys : tvp.IssuerSigningKeys.Concat(idpSigningKeys));

                if (!Options.WantAssertionsSigned) // in case they aren't signed
                {
                    tvp.RequireSignedTokens = false;
                }

                if (validator.CanReadToken(token))
                {
                    principal = validator.ValidateToken(token, tvp, out parsedToken);
                }

                if (principal == null)
                {
                    throw new SecurityTokenException("No token validator was found for the given token.");
                }

                if (Options.UseTokenLifetime && parsedToken != null)
                {
                    // Override any session persistence to match the token lifetime.
                    var issued = parsedToken.ValidFrom;
                    if (issued != DateTime.MinValue)
                    {
                        properties.IssuedUtc = issued.ToUniversalTime();
                    }
                    var expires = parsedToken.ValidTo;
                    if (expires != DateTime.MinValue)
                    {
                        properties.ExpiresUtc = expires.ToUniversalTime();
                    }
                    properties.AllowRefresh = false;
                }

                ClaimsIdentity identity = new ClaimsIdentity(principal.Claims, Scheme.Name);

                session.SessionIndex = !String.IsNullOrEmpty(session.SessionIndex) ? session.SessionIndex : assertion.ID;
                //get the session index from assertion so you can use it to logout later
                identity.AddClaim(new Claim(Saml2ClaimTypes.SessionIndex, session.SessionIndex));
                if (principal.Claims.Any(c => c.Type == ClaimTypes.NameIdentifier))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Name, principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value));
                }
                string redirectUrl = !string.IsNullOrEmpty(properties.RedirectUri) ? properties.RedirectUri : Options.CallbackPath.ToString();
                Context.Response.Redirect(redirectUrl, true);
                Context.User = new ClaimsPrincipal(identity);
                await Context.SignInAsync(Options.SignInScheme, Context.User, properties);
                return HandleRequestResult.Success(new AuthenticationTicket(Context.User, properties, Scheme.Name));
            }
            catch (Exception exception)
            {
                return HandleRequestResult.Fail(exception, properties);
            }
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
            // Save the original challenge URI so we can redirect back to it when we're done.
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

            if (Options.AssertionConsumerServiceUrl == null)
            {
                Options.AssertionConsumerServiceUrl = new Uri(new Uri(CurrentUri), Options.CallbackPath);
            }

            var saml2Message = new Saml2Message();

            //generate a nonce of random bytes and retain it in a browser cookie
            //and encode this nonce and other information in the authentication properties
            //'properties.Dictionary[correlationKey] = correlationId;'
            //this will later be passed in a state query string parameter to the
            //identity provider. The identity provider will return this value right
            //back to your application after authenticating the user.         
            GenerateCorrelationId(properties);

            //create relay state
            string relayState = Options.StateDataFormat.Protect(properties);

            //AuthnRequest ID value which needs to be included in the AuthnRequest
            //we will need this to create the same session cookie as well
            var authnRequestId = Microsoft.IdentityModel.Tokens.UniqueId.CreateRandomId();

            //create saml cookie session to check against then delete it
            //According to the SAML specification, the SAML response returned by the IdP
            //should have an InResponseTo field that matches the authn request ID. This ties the SAML
            //response to the authn request. The authn request ID is saved in the SAML session
            //state so it can be checked against the InResponseTo.

            //cleanup and remove existing saml cookies            
            Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CoreCookieName);

            //create cookie 
            Options.Saml2CoreCookie.Name = $"{Options.Saml2CoreCookieName}.{relayState.GetHashCode()}";

            // append it to response
            Response.Cookies.Append(Saml2Constants.InResponseToId, authnRequestId.Base64Encode(),
                Options.Saml2CoreCookie.Build(Context));

            var samlRequest = saml2Message.CreateSignInRequest(Options, authnRequestId, properties);

            if (Options.AuthenticationMethod == Saml2AuthenticationBehaviour.RedirectGet)
            {
                //call idp
                Response.Redirect(samlRequest);
            }
            else
            {
                var content = samlRequest;
                var buffer = Encoding.UTF8.GetBytes(content);

                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/html;charset=UTF-8";

                // Emit Cache-Control=no-cache to prevent client caching.
                Response.Headers.Add("Cache-Control", "no-cache, no-store");
                Response.Headers.Add("Pragma", "no-cache");
                Response.Headers.Add("Expires", "Thu, 01 Jan 1970 00:00:00 GMT");

                await Response.Body.WriteAsync(buffer,0, buffer.Length);
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

            //read the form data
            var form = await Request.ReadFormAsync();

            //extract the relay state and deflate
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
                    Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CoreCookieName);

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
            key.StartsWith("balh" + ".Signout"))];

            await _saml2Service.CheckIfReplayAttackAsync();
            await _saml2Service.CheckStatusAsync();

            //check to see if successfully logged out from both app and idp
            if (Context.User.Identity.IsAuthenticated)
                return false;

            await Context.SignOutAsync(Options.SignOutScheme, authenticationProperties);
            Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CoreCookieName);

            var redirectUrl = !string.IsNullOrEmpty(authenticationProperties.RedirectUri) ?
                authenticationProperties.RedirectUri : Options.DefaultRedirectUrl.ToString();

            Response.Redirect(redirectUrl, true);
            return true;
        }
    }
}


