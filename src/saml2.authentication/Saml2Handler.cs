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
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Saml2Metadata;
using Saml2Metadata.Schema;
using static Saml2Authentication.Saml2Constants;

namespace Saml2Authentication
{
    internal class Saml2Handler : RemoteAuthenticationHandler<Saml2Options>,
        IAuthenticationSignOutHandler
    {
        private readonly ILogger<Saml2Handler> _logger;
        private EntityDescriptor _configuration;
        protected HttpClient Backchannel => Options.Backchannel;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2Handler" /> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        /// <param name="encoder">The encoder.</param>
        /// <param name="clock">The clock.</param>
        public Saml2Handler(
            IOptionsMonitor<Saml2Options> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock
            ) : base(options, loggerFactory, encoder, clock)
        {
            _logger = loggerFactory.CreateLogger<Saml2Handler>();
        }
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            Saml2Message saml2Message = null;
            AuthenticationProperties properties = null;
            Saml2ParsedResponseType parsedSamlMessage;

            if (HttpMethods.IsGet(Request.Method))
            {
                var query = Request.Query;
                // ToArray handles the StringValues.IsNullOrEmpty case.
                // We assume non-empty Value does not contain null elements.
#pragma warning disable CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
                saml2Message = new Saml2Message(query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value.ToArray())));
#pragma warning restore CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
            }
            // assumption: if the ContentType is "application/x-www-form-urlencoded"
            // it should be safe to read as it is small.
            else if (HttpMethods.IsPost(Request.Method)
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
                var relayState = saml2Message.RelayState.DeflateDecompress();

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
                    saml2Message.RelayState = userState;
                }

                //it is not a saml response or an artifact message
                if (saml2Message.SamlResponse == null &&
                    saml2Message.SamlArt == null &&
                    saml2Message.ArtifactResponse == null)
                {
                    _logger.SignInWithoutWResult();
                    return HandleRequestResult.Fail(Properties.Resources.SignInMessageSamlResponseIsMissing, properties);
                }

                //if this was a samlart, then extract the saml artifact resolve value
                //and send to Idp artifact resolution service
                if (!string.IsNullOrEmpty(saml2Message.SamlArt))
                {
                    if (Options.ValidateArtifact)
                    {
                        Saml2Message.ValidateArtifact(saml2Message.SamlArt, Options);
                    }

                    var artifactResolveReceivedContext = await RunSamlArtifactResolveReceivedEventAsync(saml2Message, properties!);
                    if (artifactResolveReceivedContext.Result != null)
                    {
                        return artifactResolveReceivedContext.Result;
                    }

                    saml2Message = artifactResolveReceivedContext.ProtocolMessage;
                    properties = artifactResolveReceivedContext.Properties!;

                    var artifactResolutionRequest = artifactResolveReceivedContext.ArtifactResolutionRequest;

                    parsedSamlMessage = await RedeemFromArtifactResolveServiceAsync(saml2Message);
                }
                else
                {
                    _logger.LogDebug($"Read Saml response and vaidate signature if needed.");

                    //read saml response and vaidate signature if needed
                    parsedSamlMessage = saml2Message.GetSamlResponseToken(Saml2Constants.ResponseTypes.AuthnResponse, Options);
                }

                //since this is a solicited login (sent from challenge)
                // we must compare the incoming 'InResponseTo' what we have in the cookie
                var requestCookies = Request.Cookies;
                var inResponseToCookieValue = requestCookies[requestCookies.Keys.FirstOrDefault(key => key.StartsWith(Options.Saml2CookieName))];

                //cleanup and remove existing saml cookies
                Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CookieName);

                //validate it is not a replay attack by comparing inResponseTo values
                saml2Message.CheckIfReplayAttack(parsedSamlMessage.Response.InResponseTo, inResponseToCookieValue);

                //check what the Idp response is -if it was successful or not
                saml2Message.CheckStatus(parsedSamlMessage.Response);

                //get the token and decrypt it if it was encrypted
                var token = saml2Message.GetToken(parsedSamlMessage.Response, Options.EncryptingCertificate);

                _logger.LogDebug("Extracting Saml assertion.");
                //get the decrypted assertion section 
                //and check its signature (if that option was set to 'true')
                var assertion = saml2Message.GetAssertion(token, Options);

                _logger.LogDebug("Extracting AuthnStatement from Saml Response.");

                //we need extract the session index 
                //and save in a cookie for SLO
                var session = new AuthnStatementType();

                if (assertion.Items.Any(x => x.GetType() == typeof(AuthnStatementType)))
                {
                    session = (AuthnStatementType)assertion.Items.FirstOrDefault(x => x.GetType() == typeof(AuthnStatementType));
                    if (session == null)
                    {
                        _logger.LogDebug("Saml Response does not contain an AuthnStatement.");
                    }
                }

                //is it to be re-used for logout
                if (assertion.Subject.Items.Any(x => x.GetType() == typeof(NameIDType)))
                {
                    var nameIdType = (NameIDType)assertion.Subject.Items.FirstOrDefault(x => x.GetType() == typeof(NameIDType));

                    if (nameIdType == null)
                    {
                        _logger.LogDebug("Saml Response does not contain NameID.");
                    }

                    if (nameIdType != null)
                    {
                        _logger.LogDebug("Saml Response contains NameID.");

                        //write from incoming 
                        Options.NameId = new NameId
                        {
                            SpNameQualifier = nameIdType.SPNameQualifier,
                            Format = nameIdType.Format,
                            NameQualifier = nameIdType.NameQualifier,
                            SpProvidedId = nameIdType.SPProvidedID,
                            Value = nameIdType.Value
                        };
                    }
                }

                if (_configuration == null)
                {
                    _logger.UpdatingConfiguration();
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                    _logger.ConfigurationManagerGetConfigurationAsyncCalled();
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

                _logger.LogDebug("Setting Saml token validators.");

                var issuers = new[] { parsedSamlMessage.Response.Issuer.Value };
                tvp.ValidateIssuerSigningKey = Options.WantAssertionsSigned;
                tvp.ValidateTokenReplay = !Options.IsPassive;
                tvp.ValidateIssuer = Options.ValidateIssuer;
                tvp.ValidateAudience = Options.ValidateAudience;
                tvp.ValidAudiences = Options.ValidAudiences.Prepend(Options.EntityId);
                tvp.ValidIssuers = Options.ValidIssuers.Prepend(Options.Configuration.EntityID);
                tvp.IssuerSigningKeys = (tvp.IssuerSigningKeys == null ? idpSigningKeys
                    : tvp.IssuerSigningKeys.Concat(idpSigningKeys));

                //in case they aren't signed
                if (!Options.WantAssertionsSigned)
                {
                    tvp.RequireSignedTokens = false;
                }

                using (var sr = new StringReader(parsedSamlMessage.RawResponse))
                {
                    var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
                    using (var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr, settings)))
                    {
                        if (reader.IsStartElement(Saml2Constants.Elements.Response, Saml2Constants.Namespaces.Protocol))
                        {
                            while (reader.Read())
                            {
                                if (reader.IsStartElement())
                                {
                                    if (validator.CanReadToken(reader))
                                    {
                                        _logger.LogDebug("Validating Saml token.");
                                        principal = validator.ValidateToken(reader, tvp, out parsedToken);
                                        _logger.TokenValidatedHandledResponse();
                                        break;
                                    }
                                }
                            }
                        }
                    }
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

                _logger.RetrievingClaims();

                if (!string.IsNullOrWhiteSpace(session?.SessionIndex))
                {
                    //update the cookie with session index value
                    //will be used for logout
                    //get the session index from assertion so you can use it to logout later
                    identity.AddClaim(new Claim(Saml2ClaimTypes.SessionIndex, session.SessionIndex));
                    _logger.LogDebug($"Added session index to user claims for signout later.");
                }
                else
                {
                    _logger.LogDebug($"Session index does not exist, cannot add to user claims for signout.");
                }

                if (principal.Claims.Any(c => c.Type == ClaimTypes.NameIdentifier))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Name, principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value));
                    _logger.LogDebug($"Added name identifier to user claims.");
                }
                else
                {
                    _logger.LogDebug($"Name identifier does not exist in user claims.");
                }
                string redirectUrl = !string.IsNullOrEmpty(properties.RedirectUri) ? properties.RedirectUri : Options.CallbackPath.ToString();
                Context.Response.Redirect(redirectUrl, true);
                Context.User = new ClaimsPrincipal(identity);
                //await Context.SignInAsync(Options.SignInScheme, Context.User, properties);
                _logger.LogDebug($"Creating authentication ticket.");
                return HandleRequestResult.Success(new AuthenticationTicket(Context.User, properties, Scheme.Name));
            }
            catch (Exception exception)
            {
                return HandleRequestResult.Fail(exception, properties);
            }
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
                _logger.RemoteSignOut();
                // we've received a remote sign-out request
                return HandleRemoteSignOutAsync();
            }
            else if (Options.SignOutPath.HasValue && Options.SignOutPath == Request.Path)
            {
                _logger.SignOutCallbackRecieved();
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
            _logger.EnteringSaml2AuthenticationHandlerHandleUnauthorizedAsync(GetType().FullName!);

            // order for local RedirectUri
            // 1. challenge.Properties.RedirectUri
            // 2. CurrentUri if RedirectUri is not set)
            // Save the original challenge URI so we can redirect back to it when we're done.
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            if (_configuration == null && Options.ConfigurationManager != null)
            {
                _logger.UpdatingConfiguration();
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                _logger.ConfigurationManagerGetConfigurationAsyncCalled();
                Options.Configuration = _configuration;
            }

            if (Options.AssertionConsumerServiceUrl == null && Options.AssertionConsumerServiceIndex == null)
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
            Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CookieName);

            //create cookie 
            var cookieName = $"{Options.Saml2CookieName}.{(uint)relayState.GetHashCode()}";

            // append it to response
            Response.Cookies.Append(cookieName, authnRequestId.Base64Encode(),
                Options.Saml2Cookie.Build(Context));

            _logger.CreateSignInRequest();

            var samlRequest = saml2Message.CreateSignInRequest(Options, authnRequestId, relayState);
            _logger.SignInRequestCreated();

            if (Options.AuthenticationMethod == Saml2AuthenticationBehaviour.RedirectGet)
            {
                _logger.RedirectAuthenticationLocalRedirect(properties.RedirectUri);
                //call idp
                Response.Redirect(samlRequest);
            }
            else if (Options.AuthenticationMethod == Saml2AuthenticationBehaviour.FormPost)
            {
                _logger.PostAuthenticationLocalRedirect(properties.RedirectUri);
                var content = samlRequest;
                var buffer = Encoding.UTF8.GetBytes(content);

                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/html;charset=UTF-8";

                // Emit Cache-Control=no-cache to prevent client caching.
                Response.Headers.Add("Cache-Control", "no-cache, no-store");
                Response.Headers.Add("Pragma", "no-cache");
                Response.Headers.Add("Expires", "Thu, 01 Jan 1970 00:00:00 GMT");

                await Response.WriteAsync(content);
            }
        }

        //response from Idp based on previous logout request
        protected virtual async Task<bool> HandleSignOutCallbackAsync()
        {
            Saml2Message saml2Message = null;
            AuthenticationProperties properties = null;
            Saml2ParsedResponseType parsedSamlMessage;

            //redirect
            if (HttpMethods.IsGet(Request.Method))
            {
                _logger.LogDebug($"Read Saml logout HTTPGet response.");
                var query = Request.Query;
                // ToArray handles the StringValues.IsNullOrEmpty case.
                // We assume non-empty Value does not contain null elements.
#pragma warning disable CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
                saml2Message = new Saml2Message(query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value.ToArray())));
#pragma warning restore CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
            }
            // assumption: if the ContentType is "application/x-www-form-urlencoded"
            // it should be safe to read as it is small.
            //post
            else if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                _logger.LogDebug($"Read Saml logout HTTPPost response.");
                var form = await Request.ReadFormAsync(Context.RequestAborted);
                // ToArray handles the StringValues.IsNullOrEmpty case.
                // We assume non-empty Value does not contain null elements.
#pragma warning disable CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
                saml2Message = new Saml2Message(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value.ToArray())));
#pragma warning restore CS8620 // Argument cannot be used for parameter due to differences in the nullability of reference types.
            }

            if (saml2Message == null || !saml2Message.IsLogoutMessage)
            {
                return false;
            }
            try
            {

                //get relay
                var relayState = saml2Message.RelayState.DeflateDecompress();

                //get authentication properties
                properties = Options.StateDataFormat.Unprotect(relayState);

                // Extract the user state from properties and reset.
                properties.Items.TryGetValue(Saml2Defaults.UserstatePropertiesKey, out var userState);
                saml2Message.RelayState = userState;
                //}

                //it is not a saml response or an artifact message
                if (saml2Message.SamlResponse == null &&
                    saml2Message.SamlArt == null &&
                    saml2Message.ArtifactResponse == null)
                {
                    return false;
                }

                //if this was a samlart, then extract the saml artifact resolve value
                //and send to Idp artifact resolution service
                if (!string.IsNullOrEmpty(saml2Message.SamlArt))
                {
                    if (Options.ValidateArtifact)
                    {
                        Saml2Message.ValidateArtifact(saml2Message.SamlArt, Options);
                    }

                    var artifactResolveReceivedContext = await RunSamlArtifactResolveReceivedEventAsync(saml2Message, properties!);
                    if (artifactResolveReceivedContext.Result != null)
                    {
                        return false;
                    }

                    saml2Message = artifactResolveReceivedContext.ProtocolMessage;
                    properties = artifactResolveReceivedContext.Properties!;

                    var artifactResolutionRequest = artifactResolveReceivedContext.ArtifactResolutionRequest;

                    parsedSamlMessage = await RedeemFromArtifactResolveServiceAsync(saml2Message);
                }

                else
                {
                    _logger.LogDebug($"Read Saml logout response and vaidate signature if needed.");
                    //read saml logout response and vaidate signature if needed
                    parsedSamlMessage = saml2Message.GetSamlResponseToken(Saml2Constants.ResponseTypes.LogoutResponse, Options);
                }

                //since this is a solicited login (sent from challenge)
                // we must compare the incoming 'InResponseTo' what we have in the cookie
                var requestCookies = Request.Cookies;
                var inResponseToCookieValue = requestCookies[requestCookies.Keys.FirstOrDefault(key => key.StartsWith(Options.Saml2CookieName))];

                //validate it is not a replay attack by comparing inResponseTo values
                saml2Message.CheckIfReplayAttack(parsedSamlMessage.Response.InResponseTo, inResponseToCookieValue);

                //cleanup and remove existing saml cookies
                //no need for it since we checked the inResponseId values
                Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CookieName);

                //check what the Idp response is -if it was successful or not
                saml2Message.CheckStatus(parsedSamlMessage.Response);

                if (Context.User.Identity.IsAuthenticated)
                {
                    _logger.LogDebug($"Sign user out.");
                    await Context.SignOutAsync(Options.SignOutScheme, properties);
                }

                var redirectUrl = !string.IsNullOrEmpty(properties.RedirectUri) ?
                    properties.RedirectUri : Options.DefaultRedirectUrl.ToString();
                Response.Redirect(redirectUrl, true);

                return true;
            }
            catch (Exception exception)
            {
                var message = exception.Message;
                return false;
            }
        }

        //sp initiated single logout
        public virtual async Task SignOutAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignOut);
            if (target != null)
            {
                await Context.SignOutAsync(target, properties);
                return;
            }
            if (_configuration == null && Options.ConfigurationManager != null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                Options.Configuration = _configuration;
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

            //LogoutRequest ID value which needs to be included in the AuthnRequest
            //we will need this to create the same session cookie as well
            var logoutRequestId = Microsoft.IdentityModel.Tokens.UniqueId.CreateRandomId();

            //get session index value
            var sessionIndex = Context.User.Claims.FirstOrDefault(c => c.Type == Saml2ClaimTypes.SessionIndex)?.Value;

            if (string.IsNullOrWhiteSpace(sessionIndex))
            {
                throw new Saml2Exception("Session index value not found. This is required for SAML signout.");
            }

            //get nameId value
            if (string.IsNullOrEmpty(Options.NameId?.Value))
            {
                Options.NameId = new NameId
                {
                    Value = Context.User.FindFirst(ClaimTypes.NameIdentifier).Value
                };
            }

            //create saml cookie session to check against then delete it
            //According to the SAML specification, the SAML response returned by the IdP
            //should have an InResponseTo field that matches the authn request ID. This ties the SAML
            //response to the authn request. The logout request ID is saved in the SAML session
            //state so it can be checked against the InResponseTo.

            //cleanup and remove existing saml cookies
            Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CookieName);

            //create cookie 
            var cookieName = $"{Options.Saml2CookieName}.{(uint)relayState.GetHashCode()}";

            // append it to response
            Response.Cookies.Append(cookieName, logoutRequestId.Base64Encode(),
                Options.Saml2Cookie.Build(Context));

            //if logout is redirect
            if (Options.LogoutMethod == Saml2LogoutBehaviour.RedirectGet)
            {
                _logger.LogDebug($"Creating redirect signout request.");
                var samlRequest = saml2Message.CreateLogoutRequest(Options, logoutRequestId, sessionIndex, relayState);
                //call idp
                Response.Redirect(samlRequest);
            }

            //if logout is post 
            else if (Options.LogoutMethod == Saml2LogoutBehaviour.FormPost)
            {
                _logger.LogDebug($"Creating post signout request.");
                var samlRequest = saml2Message.CreateLogoutRequest(Options, logoutRequestId, sessionIndex, relayState);
                var content = samlRequest;
                var buffer = Encoding.UTF8.GetBytes(content);

                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/html;charset=UTF-8";

                await Response.WriteAsync(content);
            }
        }


        //idp sending a fan logout request
        protected virtual async Task<bool> HandleRemoteSignOutAsync()
        {
            //TODO SLO
            return await Task.FromResult(true);
        }


        protected virtual async Task<Saml2ParsedResponseType> RedeemFromArtifactResolveServiceAsync(Saml2Message saml2Message)
        {
            _logger.RedeemingArtifactForAssertion();

            var artifactValue = Saml2Message.GetArtifact(saml2Message.SamlArt);
            var arsIndex = (ushort)artifactValue.EndpointIndex;

            //use the index that was in the returned parsed artifact object
            var requestMessage = new HttpRequestMessage(HttpMethod.Post,
                Saml2Message.GetIdpDescriptor(Options.Configuration).ArtifactResolutionServices
                .FirstOrDefault(x => x.Index == arsIndex).Location);

            //artifact ID value which needs to be included in the artifact resolve request
            //we will need this to create the same session cookie as well
            var authnRequestId2 = Microsoft.IdentityModel.Tokens.UniqueId.CreateRandomId();

            var artifactResolveRequest = new Saml2Message()
                .CreateArtifactResolutionSigninRequest(Options, authnRequestId2, saml2Message.SamlArt);

            requestMessage.Headers.Add(Parameters.SOAPAction, Artifacts.SoapAction);
            requestMessage.Content = new StringContent(artifactResolveRequest, Encoding.UTF8, "text/xml");
            requestMessage.Version = new Version(2, 0);

            //send soap message
            var responseMessage = await Backchannel.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);

            var contentMediaType = responseMessage.Content.Headers.ContentType?.MediaType;
            if (string.IsNullOrEmpty(contentMediaType))
            {
                _logger.LogDebug($"Unexpected token response format. Status Code: {(int)responseMessage.StatusCode}. Content-Type header is missing.");
            }
            else if (!string.Equals(contentMediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogDebug($"Unexpected token response format. Status Code: {(int)responseMessage.StatusCode}. Content-Type {responseMessage.Content.Headers.ContentType}.");
            }

            try
            {
                var responseContent = await responseMessage.Content.ReadAsStringAsync();
                saml2Message.ArtifactResponse = responseContent;
            }
            catch (Exception ex)
            {
                throw new Saml2Exception($"Failed to parse token response body as JSON. Status Code: {(int)responseMessage.StatusCode}. Content-Type: {responseMessage.Content.Headers.ContentType}", ex);
            }

            if (!responseMessage.IsSuccessStatusCode)
            {
                throw new Saml2Exception(responseMessage.ReasonPhrase);
            }
            _logger.ArtifactResolutionResponeReceived();
            return saml2Message.GetArtifactResponseToken(saml2Message.ArtifactResponse, Options);
        }

        #region Private

        private async Task<ArtifactResolveReceivedContext> RunSamlArtifactResolveReceivedEventAsync(Saml2Message saml2Message,
            AuthenticationProperties properties)
        {
            _logger.ArtifactResolveReceived();

            var saml2message = new Saml2Message()
            {
                SamlArt = saml2Message.SamlArt,
            };

            var context = new ArtifactResolveReceivedContext(Context, Scheme, Options, properties)
            {
                ProtocolMessage = saml2Message,
                Backchannel = Backchannel
            };

            await Events.ArtifactResolveReceived(context);
            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    _logger.ArtifactResolveReceivedContextHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    _logger.ArtifactResolveReceivedContextSkipped();
                }
            }
            return context;
        }
        #endregion
    }
}


