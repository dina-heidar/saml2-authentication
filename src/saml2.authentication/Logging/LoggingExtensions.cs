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

using Microsoft.Extensions.Logging;

namespace Saml2Core
{
    internal static partial class Log
    {
        [LoggerMessage(1, LogLevel.Debug, "Received a sign-in message without a SamlResponse.", EventName = "SignInWithoutWResult")]
        public static partial void SignInWithoutWResult(this ILogger logger);

        [LoggerMessage(13, LogLevel.Debug, "Updating configuration", EventName = "UpdatingConfiguration")]
        public static partial void UpdatingConfiguration(this ILogger logger);

        [LoggerMessage(18, LogLevel.Debug, "Retrieve the current configuration, refreshing and/or caching as needed.", EventName = "ConfigurationManagerRequestRefreshCalled")]
        public static partial void ConfigurationManagerGetConfigurationAsyncCalled(this ILogger logger);

        [LoggerMessage(27, LogLevel.Debug, "Saml artifact resolve received.", EventName = "ArtifactResolveReceived")]
        public static partial void ArtifactResolveReceived(this ILogger logger);

        [LoggerMessage(30, LogLevel.Debug, "Artifact resolution response received.", EventName = "ArtifactResolutionResponeReceived")]
        public static partial void ArtifactResolutionResponeReceived(this ILogger logger);

        [LoggerMessage(19, LogLevel.Debug, "Redeeming artifact for assertion.", EventName = "RedeemingArtifactForAssertion")]
        public static partial void RedeemingArtifactForAssertion(this ILogger logger);

        [LoggerMessage(15, LogLevel.Debug, "TokenValidated.HandledResponse", EventName = "TokenValidatedHandledResponse")]
        public static partial void TokenValidatedHandledResponse(this ILogger logger);

        //[LoggerMessage(16, LogLevel.Debug, "TokenValidated.Skipped", EventName = "TokenValidatedSkipped")]
        //public static partial void TokenValidatedSkipped(this ILogger logger);

        [LoggerMessage(28, LogLevel.Debug, "ArtifactResolveReceivedContext.HandledResponse", EventName = "ArtifactResolveReceivedContextHandledResponse")]
        public static partial void ArtifactResolveReceivedContextHandledResponse(this ILogger logger);

        [LoggerMessage(29, LogLevel.Debug, "ArtifactResolveReceivedContext.Skipped", EventName = "ArtifactResolveReceivedContextSkipped")]
        public static partial void ArtifactResolveReceivedContextSkipped(this ILogger logger);

        //[LoggerMessage(31, LogLevel.Debug, "TokenResponseReceived.HandledResponse", EventName = "TokenResponseReceivedHandledResponse")]
        //public static partial void TokenResponseReceivedHandledResponse(this ILogger logger);

        //[LoggerMessage(32, LogLevel.Debug, "TokenResponseReceived.Skipped", EventName = "TokenResponseReceivedSkipped")]
        //public static partial void TokenResponseReceivedSkipped(this ILogger logger);

        [LoggerMessage(38, LogLevel.Debug, "AuthenticationFailedContext.HandledResponse", EventName = "AuthenticationFailedContextHandledResponse")]
        public static partial void AuthenticationFailedContextHandledResponse(this ILogger logger);

        //[LoggerMessage(39, LogLevel.Debug, "AuthenticationFailedContext.Skipped", EventName = "AuthenticationFailedContextSkipped")]
        //public static partial void AuthenticationFailedContextSkipped(this ILogger logger);

        //[LoggerMessage(24, LogLevel.Debug, "MessageReceived: '{RedirectUrl}'.", EventName = "MessageReceived")]
        //public static partial void MessageReceived(this ILogger logger, string redirectUrl);

        //[LoggerMessage(25, LogLevel.Debug, "MessageReceivedContext.HandledResponse", EventName = "MessageReceivedContextHandledResponse")]
        //public static partial void MessageReceivedContextHandledResponse(this ILogger logger);

        //[LoggerMessage(26, LogLevel.Debug, "MessageReceivedContext.Skipped", EventName = "MessageReceivedContextSkipped")]
        //public static partial void MessageReceivedContextSkipped(this ILogger logger);

        //[LoggerMessage(1, LogLevel.Debug, "RedirectToIdentityProviderForSignOut.HandledResponse", EventName = "RedirectToIdentityProviderForSignOutHandledResponse")]
        //public static partial void RedirectToIdentityProviderForSignOutHandledResponse(this ILogger logger);

        //[LoggerMessage(6, LogLevel.Debug, "RedirectToIdentityProvider.HandledResponse", EventName = "RedirectToIdentityProviderHandledResponse")]
        //public static partial void RedirectToIdentityProviderHandledResponse(this ILogger logger);

        [LoggerMessage(50, LogLevel.Debug, "SignOut callback recieved")]
        public static partial void SignOutCallbackRecieved(this ILogger logger);

        //[LoggerMessage(51, LogLevel.Debug, "RedirectToSignedOutRedirectUri.Skipped", EventName = "SignOutCallbackRedirectSkipped")]
        //public static partial void SignOutCallbackRedirectSkipped(this ILogger logger);

        //[LoggerMessage(3, LogLevel.Warning, "The query string for Logout is not a well-formed URI. Redirect URI: '{RedirectUrl}'.", EventName = "InvalidLogoutQueryStringRedirectUrl")]
        //public static partial void InvalidLogoutQueryStringRedirectUrl(this ILogger logger, string redirectUrl);

        //[LoggerMessage(10, LogLevel.Debug, "message.State is null or empty.", EventName = "NullOrEmptyAuthorizationResponseState")]
        //public static partial void NullOrEmptyAuthorizationResponseState(this ILogger logger);

        //[LoggerMessage(11, LogLevel.Debug, "Unable to read the message.State.", EventName = "UnableToReadAuthorizationResponseState")]
        //public static partial void UnableToReadAuthorizationResponseState(this ILogger logger);

        //[LoggerMessage(12, LogLevel.Error, "Message contains error: '{Error}', error_description: '{ErrorDescription}', error_uri: '{ErrorUri}'.", EventName = "ResponseError")]
        //public static partial void ResponseError(this ILogger logger, string error, string errorDescription, string errorUri);

        [LoggerMessage(52, LogLevel.Error, "Message contains error: '{Error}', error_description: '{ErrorDescription}', error_uri: '{ErrorUri}', status code '{StatusCode}'.", EventName = "ResponseErrorWithStatusCode")]
        public static partial void ResponseErrorWithStatusCode(this ILogger logger, string error, string errorDescription, string errorUri, int statusCode);

        //[LoggerMessage(17, LogLevel.Error, "Exception occurred while processing message.", EventName = "ExceptionProcessingMessage")]
        //public static partial void ExceptionProcessingMessage(this ILogger logger, Exception ex);

        [LoggerMessage(20, LogLevel.Debug, "Retrieving claims assertion.")]
        public static partial void RetrievingClaims(this ILogger logger);

        //[LoggerMessage(23, LogLevel.Warning, "Failed to un-protect the nonce cookie.", EventName = "UnableToProtectNonceCookie")]
        //public static partial void UnableToProtectNonceCookie(this ILogger logger, Exception ex);

        //[LoggerMessage(8, LogLevel.Warning, "The redirect URI is not well-formed. The URI is: '{AuthenticationRequestUrl}'.", EventName = "InvalidAuthenticationRequestUrl")]
        //public static partial void InvalidAuthenticationRequestUrl(this ILogger logger, string authenticationRequestUrl);

        //[LoggerMessage(43, LogLevel.Error, "Unable to read the 'id_token', no suitable ISecurityTokenValidator was found for: '{IdToken}'.", EventName = "UnableToReadIdToken")]
        //public static partial void UnableToReadIdToken(this ILogger logger, string idToken);

        //[LoggerMessage(40, LogLevel.Error, "The Validated Security Token must be of type JwtSecurityToken, but instead its type is: '{SecurityTokenType}'", EventName = "InvalidSecurityTokenType")]
        //public static partial void InvalidSecurityTokenType(this ILogger logger, string? securityTokenType);

        [LoggerMessage(4, LogLevel.Debug, "Entering {Saml2HandlerType}'s HandleUnauthorizedAsync.", EventName = "EnteringSaml2AuthenticationHandlerHandleUnauthorizedAsync")]
        public static partial void EnteringSaml2AuthenticationHandlerHandleUnauthorizedAsync(this ILogger logger, string saml2HandlerType);

        [LoggerMessage(5, LogLevel.Debug, "Post authentication: '{RedirectUri}'.", EventName = "PostAuthenticationLocalRedirect")]
        public static partial void PostAuthenticationLocalRedirect(this ILogger logger, string redirectUri);

        [LoggerMessage(6, LogLevel.Debug, "Redirect authentication: '{RedirectUri}'.", EventName = "RedirectAuthenticationLocalRedirect")]
        public static partial void RedirectAuthenticationLocalRedirect(this ILogger logger, string redirectUri);

        [LoggerMessage(7, LogLevel.Debug, "Create signin request.")]
        public static partial void CreateSignInRequest(this ILogger logger);

        [LoggerMessage(8, LogLevel.Debug, "Signin request created.")]
        public static partial void SignInRequestCreated(this ILogger logger);

        //[LoggerMessage(33, LogLevel.Debug, "Using properties.RedirectUri for redirect post authentication: '{RedirectUri}'.", EventName = "PostSignOutRedirect")]
        //public static partial void PostSignOutRedirect(this ILogger logger, string redirectUri);

        //[LoggerMessage(44, LogLevel.Debug, "RemoteSignOutContext.HandledResponse", EventName = "RemoteSignOutHandledResponse")]
        //public static partial void RemoteSignOutHandledResponse(this ILogger logger);

        //[LoggerMessage(45, LogLevel.Debug, "RemoteSignOutContext.Skipped", EventName = "RemoteSignOutSkipped")]
        //public static partial void RemoteSignOutSkipped(this ILogger logger);

        [LoggerMessage(46, LogLevel.Debug, "Remote signout request processed.", EventName = "RemoteSignOut")]
        public static partial void RemoteSignOut(this ILogger logger);

        //[LoggerMessage(47, LogLevel.Error, "The remote signout request was ignored because the 'sid' parameter " +
        //                     "was missing, which may indicate an unsolicited logout.", EventName = "RemoteSignOutSessionIdMissing")]
        //public static partial void RemoteSignOutSessionIdMissing(this ILogger logger);

        //[LoggerMessage(48, LogLevel.Error, "The remote signout request was ignored because the 'sid' parameter didn't match " +
        //                     "the expected value, which may indicate an unsolicited logout.", EventName = "RemoteSignOutSessionIdInvalid")]
        //public static partial void RemoteSignOutSessionIdInvalid(this ILogger logger);

        [LoggerMessage(49, LogLevel.Debug, "AuthenticationScheme: {AuthenticationScheme} signed out.", EventName = "AuthenticationSchemeSignedOut")]
        public static partial void AuthenticationSchemeSignedOut(this ILogger logger, string authenticationScheme);

        [LoggerMessage(53, LogLevel.Debug, "HandleChallenge with Location: {Location}; and Set-Cookie: {Cookie}.", EventName = "HandleChallenge")]
        public static partial void HandleChallenge(this ILogger logger, string location, string cookie);

        //[LoggerMessage(54, LogLevel.Error, "The remote signout request was ignored because the 'iss' parameter " +
        //                    "was missing, which may indicate an unsolicited logout.", EventName = "RemoteSignOutIssuerMissing")]
        //public static partial void RemoteSignOutIssuerMissing(this ILogger logger);

        //[LoggerMessage(55, LogLevel.Error, "The remote signout request was ignored because the 'iss' parameter didn't match " +
        //                     "the expected value, which may indicate an unsolicited logout.", EventName = "RemoteSignOutIssuerInvalid")]
        //public static partial void RemoteSignOutIssuerInvalid(this ILogger logger);
    }
}
