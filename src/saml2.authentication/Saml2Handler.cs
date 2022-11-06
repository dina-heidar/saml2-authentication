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
                    Logger.SignInWithoutWResult();
                    return HandleRequestResult.Fail(Properties.Resources.SignInMessageSamlResponseIsMissing, properties);
                }

                //if this was a samlart extract the saml artifact resolve value
                //and send to Idp artifact resolution service
                if (!string.IsNullOrEmpty(saml2Message.SamlArt))
                {
                    var artifactResolveReceivedContext = await RunSamlArtifactResolveReceivedEventAsync(saml2Message, properties!);
                    if (artifactResolveReceivedContext.Result != null)
                    {
                        return artifactResolveReceivedContext.Result;
                    }

                    saml2Message = artifactResolveReceivedContext.ProtocolMessage;                   
                    properties = artifactResolveReceivedContext.Properties!;

                    var artifactResolutionRequest = artifactResolveReceivedContext.ArtifactResolutionRequest;


                    var t = await RedeemFromArtifactResolAsync(saml2Message);

                    // If the developer redeemed the code themselves...
                    //artifactResolutionResponse = artifactReceivedContext.ArtifactResolutionResponse;
                   

                    //if (artifactReceivedContext.HandledArtifactResolveRedemption)
                    //{
                    //    artifactResolutionResponse = await RedeemFromArtifactResolAsync(artifactResolutionRequest!);
                    //}                   
                }



                //since this is a solicited login (sent from challenge)
                // we must compare the incoming 'InResponseTo' what we have in the cookie
                var requestCookies = Request.Cookies;
                var inResponseToCookieValue = requestCookies[requestCookies.Keys.FirstOrDefault(key => key.StartsWith(Options.Saml2CoreCookie.Name))];

                //read saml response and vaidate signature if needed
                var responseToken = saml2Message.GetSamlResponseToken(saml2Message.SamlResponse, Options);

                //validate it is not a replay attack by comparing inResponseTo values
                saml2Message.CheckIfReplayAttack(responseToken.InResponseTo, inResponseToCookieValue);

                //cleanup and remove existing saml cookies
                //no need for it since we checked the inResponseId values
                Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CoreCookieName);

                //check what the Idp response is -if it was successful or not
                saml2Message.CheckStatus(responseToken);

                //get the token and decrypt it is it was encrypted
                var token = saml2Message.GetToken(responseToken, Options.EncryptingCertificate);

                //get the decrypted assertion section 
                //and check its signature (if that option was set to 'true')
                var assertion = saml2Message.GetAssertion(token, Options);

                //we need extract the session index 
                //and save in a cookie for SLO
                var session = new AuthnStatementType();

                if (assertion.Items.Any(x => x.GetType() == typeof(AuthnStatementType)))
                {
                    session = (AuthnStatementType)assertion.Items.FirstOrDefault(x => x.GetType() == typeof(AuthnStatementType));
                }

                //TODO
                //what was this for 
                //is it to be re-used for logout?
                if (assertion.Subject.Items.Any(x => x.GetType() == typeof(NameIDType)))
                {
                    var nameIdType = (NameIDType)assertion.Subject.Items.FirstOrDefault(x => x.GetType() == typeof(NameIDType));
                    Options.NameIdPolicy = new NameIdPolicy
                    {
                        SpNameQualifier = nameIdType.SPNameQualifier,
                        Format = nameIdType.Format
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
                //await Context.SignInAsync(Options.SignInScheme, Context.User, properties);
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
            Logger.EnteringSaml2AuthenticationHandlerHandleUnauthorizedAsync(GetType().FullName!);

            // order for local RedirectUri
            // 1. challenge.Properties.RedirectUri
            // 2. CurrentUri if RedirectUri is not set)
            // Save the original challenge URI so we can redirect back to it when we're done.
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            Logger.PostAuthenticationLocalRedirect(properties.RedirectUri);

            if (_configuration == null && Options.ConfigurationManager != null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
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
            Response.DeleteAllSaml2RequestCookies(Context.Request, Options.Saml2CoreCookieName);

            //create cookie 
            Options.Saml2CoreCookie.Name = $"{Options.Saml2CoreCookieName}.{(uint)relayState.GetHashCode()}";

            // append it to response
            Response.Cookies.Append(Options.Saml2CoreCookie.Name, authnRequestId.Base64Encode(),
                Options.Saml2CoreCookie.Build(Context));

            var samlRequest = saml2Message.CreateSignInRequest(Options, authnRequestId, relayState);

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

                await Response.WriteAsync(content);
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

        protected virtual async Task<Saml2Message> RedeemFromArtifactResolAsync(Saml2Message saml2Message)
        {
            Logger.RedeemingArtifactForAssertion();
           
            var requestMessage = new HttpRequestMessage(HttpMethod.Post,
                Saml2Message.GetIdpDescriptor(Options.Configuration).ArtifactResolutionServices
                .FirstOrDefault(x => x.Index == Options.ArtifactResolutionServiceIndex).Location);

            //AuthnRequest ID value which needs to be included in the AuthnRequest
            //we will need this to create the same session cookie as well
            var authnRequestId2 = Microsoft.IdentityModel.Tokens.UniqueId.CreateRandomId();

            var artifactResolveRequest = new Saml2Message().CreateArtifactResolutionRequest(Options, authnRequestId2, saml2Message.SamlArt);

            requestMessage.Headers.Add("SOAPAction", "");
            requestMessage.Content = new StringContent(artifactResolveRequest, Encoding.UTF8, "text/xml");
            requestMessage.Version = new Version(2, 0);// Backchannel.Version; // DefaultRequestVersion;

            //send soap message
            var responseMessage = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);

           

            var contentMediaType = responseMessage.Content.Headers.ContentType?.MediaType;
            if (string.IsNullOrEmpty(contentMediaType))
            {
                Logger.LogDebug($"Unexpected token response format. Status Code: {(int)responseMessage.StatusCode}. Content-Type header is missing.");
            }
            else if (!string.Equals(contentMediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogDebug($"Unexpected token response format. Status Code: {(int)responseMessage.StatusCode}. Content-Type {responseMessage.Content.Headers.ContentType}.");
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

            return saml2Message;
        }

        #region Private

        private async Task<ArtifactResolveReceivedContext> RunSamlArtifactResolveReceivedEventAsync(Saml2Message saml2Message, 
            AuthenticationProperties properties)
        {
            Logger.ArtifactResolveReceived();

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
                    Logger.ArtifactResolveReceivedContextHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    Logger.ArtifactResolveReceivedContextSkipped();
                }
            }

            return context;
        }
        #endregion
    }
}


