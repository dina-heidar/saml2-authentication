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

namespace Saml2Core
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
        public void Configure(string? name, Saml2Options options)
        {
            if (string.IsNullOrEmpty(name))
            {
                return;
            }

            //inherited
            options.BackchannelTimeout = StringHelpers.ParseValueOrDefault(null, _invariantTimeSpanParse, options.BackchannelTimeout);
            options.CallbackPath = new PathString(options.CallbackPath.Value);
            options.ClaimsIssuer = options.ClaimsIssuer;
            options.ForwardAuthenticate = options.ForwardAuthenticate;
            options.ForwardChallenge = options.ForwardChallenge;
            options.ForwardDefault = options.ForwardDefault;
            options.ForwardForbid = options.ForwardForbid;
            options.ForwardSignIn = options.ForwardSignIn;
            options.ForwardSignOut = options.ForwardSignOut;
            options.RemoteAuthenticationTimeout = StringHelpers.ParseValueOrDefault(null, _invariantTimeSpanParse, options.RemoteAuthenticationTimeout);
            options.RemoteSignOutPath = options.RemoteSignOutPath.Value;
            options.SaveTokens = options.SaveTokens;
            options.SignedOutRedirectUri = options.SignedOutRedirectUri;
            options.SignInScheme = options.SignInScheme;

            SetCookie(options.CorrelationCookie);
            options.MaxAge = StringHelpers.ParseValueOrDefault(null, _invariantNullableTimeSpanParse, options.MaxAge);
            SetCookie(options.Saml2CoreCookie);

            //saml2 options
            options.ArtifactResolutionPath = options.ArtifactResolutionPath;
            options.AssertionConsumerServiceIndex = options.AssertionConsumerServiceIndex;
            options.AssertionConsumerServiceUrl = options.AssertionConsumerServiceUrl;
            options.AuthenticationMethod = options.AuthenticationMethod;
            options.AuthenticationScheme = options.AuthenticationScheme;
            options.CookieConsentNeeded = options.CookieConsentNeeded;
            options.CreateMetadataFile = options.CreateMetadataFile;
            options.DefaultMetadataFolderLocation = options.DefaultMetadataFolderLocation;
            options.DefaultMetadataFileName = options.DefaultMetadataFileName;
            options.DefaultRedirectUrl = options.DefaultRedirectUrl;
            options.EntityId = options.EntityId;
            options.ForceAuthn = options.ForceAuthn;           
            options.IsPassive = options.IsPassive;
            options.LogoutChannel = options.LogoutChannel;
            options.LogoutMethod = options.LogoutMethod;
            options.MetadataAddress = options.MetadataAddress;
            options.RemoteSignOutPath = options.RemoteSignOutPath;
            options.RequireHttpsMetadata = options.RequireHttpsMetadata;
            options.RequireMessageSigned = options.RequireMessageSigned;
            options.ResponseProtocolBinding = options.ResponseProtocolBinding;           
            options.Saml2CoreCookieName = options.Saml2CoreCookieName;
            options.SignOutPath = options.SignOutPath.Value;
            options.SignedOutRedirectUri = options.SignedOutRedirectUri;
            options.SignOutScheme = options.SignOutScheme;
            options.SigningCertificate = options.SigningCertificate;
            options.SigningCertificateHashAlgorithmName = options.SigningCertificateHashAlgorithmName;
            options.UseTokenLifetime = options.UseTokenLifetime;
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
            cookieBuilder.Expiration = StringHelpers.ParseValueOrDefault(null, _invariantNullableTimeSpanParse, cookieBuilder.Expiration);
            cookieBuilder.MaxAge = StringHelpers.ParseValueOrDefault<TimeSpan?>(null, _invariantNullableTimeSpanParse, cookieBuilder.MaxAge);
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


