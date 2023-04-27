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
using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Saml2Authentication
{
    internal sealed class Saml2ConfigureOptions : IConfigureNamedOptions<Saml2Options>
    {
        private static readonly Func<string, TimeSpan> _invariantTimeSpanParse = (string timespanString) => TimeSpan.Parse(timespanString, CultureInfo.InvariantCulture);
        private static readonly Func<string, TimeSpan?> _invariantNullableTimeSpanParse = (string timespanString) => TimeSpan.Parse(timespanString, CultureInfo.InvariantCulture);

        /// <summary>
        /// Configures the specified name.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        public void Configure(string name, Saml2Options options)
        {
            if (string.IsNullOrEmpty(name))
            {
                return;
            }

            //inherited
            options.BackchannelTimeout = StringExtensions.ParseValueOrDefault(null, _invariantTimeSpanParse, options.BackchannelTimeout);
            options.CallbackPath = new PathString(options.CallbackPath.Value);
            options.ClaimsIssuer = options.ClaimsIssuer;
            options.ForwardAuthenticate = options.ForwardAuthenticate;
            options.ForwardChallenge = options.ForwardChallenge;
            options.ForwardDefault = options.ForwardDefault;
            options.ForwardForbid = options.ForwardForbid;
            options.ForwardSignIn = options.ForwardSignIn;
            options.ForwardSignOut = options.ForwardSignOut;
            options.RemoteAuthenticationTimeout = StringExtensions.ParseValueOrDefault(null, _invariantTimeSpanParse, options.RemoteAuthenticationTimeout);
            options.RemoteSignOutPath = options.RemoteSignOutPath.Value;
            options.SaveTokens = options.SaveTokens;
            options.SignedOutRedirectUri = options.SignedOutRedirectUri;
            options.SignInScheme = options.SignInScheme;

            SetCookie(options.CorrelationCookie);
            options.MaxAge = StringExtensions.ParseValueOrDefault(null, _invariantNullableTimeSpanParse, options.MaxAge);
            SetCookie(options.Saml2Cookie);

            //saml2 options
            options.AssertionConsumerServiceIndex = options.AssertionConsumerServiceIndex;
            options.AssertionConsumerServiceUrl = options.AssertionConsumerServiceUrl;
            options.AuthenticationMethod = options.AuthenticationMethod;
            options.AuthenticationRequestSigned = options.AuthenticationRequestSigned;
            options.AuthenticationScheme = options.AuthenticationScheme;
            options.CreateMetadataFile = options.CreateMetadataFile;
            options.CookieConsentNeeded = options.CookieConsentNeeded;
            options.DefaultMetadataFolderLocation = options.DefaultMetadataFolderLocation;
            options.DefaultMetadataFileName = options.DefaultMetadataFileName;
            options.DefaultRedirectUrl = options.DefaultRedirectUrl;
            options.EncryptingCertificate = options.EncryptingCertificate;
            options.EntityId = options.EntityId;
            options.Events = options.Events;
            options.ForceAuthn = options.ForceAuthn;
            options.IdpSingleSignOnServiceLocationIndex = options.IdpSingleSignOnServiceLocationIndex;
            options.IdpSingleLogoutServiceLocationIndex = options.IdpSingleLogoutServiceLocationIndex;
            options.IsPassive = options.IsPassive;
            options.LogoutMethod = options.LogoutMethod;
            options.LogoutRequestSigned = options.LogoutRequestSigned;
            options.Metadata = options.Metadata;
            options.MetadataAddress = options.MetadataAddress;
            options.NameId = options.NameId;
            options.NameIdPolicy = options.NameIdPolicy;
            options.RefreshOnIssuerKeyNotFound = options.RefreshOnIssuerKeyNotFound;
            options.RemoteSignOutPath = options.RemoteSignOutPath;
            options.RequestedAuthnContext = options.RequestedAuthnContext;
            options.RequireHttpsMetadata = options.RequireHttpsMetadata;
            options.RequireMessageSigned = options.RequireMessageSigned;
            options.ResponseLogoutBinding = options.ResponseLogoutBinding;
            options.ResponseProtocolBinding = options.ResponseProtocolBinding;
            options.Saml2CookieName = options.Saml2CookieName;
            options.SignOutPath = options.SignOutPath.Value;
            options.SigningCertificate = options.SigningCertificate;
            options.SigningCertificateHashAlgorithmName = options.SigningCertificateHashAlgorithmName;
            options.SignedOutRedirectUri = options.SignedOutRedirectUri;
            options.SignOutScheme = options.SignOutScheme;
            options.SkipUnrecognizedRequests = options.SkipUnrecognizedRequests;
            options.UseTokenLifetime = options.UseTokenLifetime;
            options.ValidateArtifact = options.ValidateArtifact;
            options.ValidateAudience = options.ValidateAudience;
            options.ValidAudiences = options.ValidAudiences;
            options.ValidateIssuer = options.ValidateIssuer;
            options.ValidIssuers = options.ValidIssuers;
            //options.ValidateMetadata = options.ValidateMetadata;
            options.VerifySignatureOnly = options.VerifySignatureOnly;
            options.WantAssertionsSigned = options.WantAssertionsSigned;
            options.SignOutQueryString = options.SignOutQueryString;
        }

        private static void SetCookie(CookieBuilder cookieBuilder)
        {
            // Override the existing defaults when values are set instead of constructing
            // an entirely new CookieBuilder.
            cookieBuilder.Domain = cookieBuilder.Domain;
            cookieBuilder.HttpOnly = cookieBuilder.HttpOnly;
            cookieBuilder.IsEssential = cookieBuilder.IsEssential;
            cookieBuilder.Expiration = StringExtensions.ParseValueOrDefault(null, _invariantNullableTimeSpanParse, cookieBuilder.Expiration);
            cookieBuilder.MaxAge = StringExtensions.ParseValueOrDefault<TimeSpan?>(null, _invariantNullableTimeSpanParse, cookieBuilder.MaxAge);
            cookieBuilder.Name = cookieBuilder.Name;
            cookieBuilder.Path = cookieBuilder.Path;
            cookieBuilder.SameSite = cookieBuilder.SameSite;
            cookieBuilder.SecurePolicy = cookieBuilder.SecurePolicy;
        }

        /// <inheritdoc />
        public void Configure(Saml2Options options)
        {
            Configure(Options.DefaultName, options);
        }
    }
}


