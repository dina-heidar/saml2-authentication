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
using Saml2Core.Helpers;

namespace Saml2Core
{
    internal sealed class Saml2ConfigureOptions : IConfigureNamedOptions<Saml2Options>
    {
        private static readonly Func<string, TimeSpan> _invariantTimeSpanParse = (string timespanString) => TimeSpan.Parse(timespanString, CultureInfo.InvariantCulture);
        private static readonly Func<string, TimeSpan?> _invariantNullableTimeSpanParse = (string timespanString) => TimeSpan.Parse(timespanString, CultureInfo.InvariantCulture);

        public void Configure(string? name, Saml2Options options)
        {
            if (string.IsNullOrEmpty(name))
            {
                return;
            }

            options.BackchannelTimeout = StringHelpers.ParseValueOrDefault(null, _invariantTimeSpanParse, options.BackchannelTimeout);
            options.CallbackPath = new PathString(options.CallbackPath.Value);
            options.ClaimsIssuer = options.ClaimsIssuer;

            //SetCookieFromConfig(configSection.GetSection(nameof(options.CorrelationCookie)), options.CorrelationCookie);

          
            options.ForwardAuthenticate = options.ForwardAuthenticate;
            options.ForwardChallenge = options.ForwardChallenge;
            options.ForwardDefault = options.ForwardDefault;
            options.ForwardForbid = options.ForwardForbid;
            options.ForwardSignIn = options.ForwardSignIn;
            options.ForwardSignOut = options.ForwardSignOut;

            //options.MaxAge = StringHelpers.ParseValueOrDefault(null, _invariantNullableTimeSpanParse, options.MaxAge);
            options.MetadataAddress = options.MetadataAddress;

            //SetCookieFromConfig(configSection.GetSection(nameof(options.NonceCookie)), options.NonceCookie);

           
            options.RemoteAuthenticationTimeout = StringHelpers.ParseValueOrDefault(null, _invariantTimeSpanParse, options.RemoteAuthenticationTimeout);
            options.RemoteSignOutPath =  options.RemoteSignOutPath.Value;
            options.RequireHttpsMetadata = options.RequireHttpsMetadata;
           
           
            options.SaveTokens =  options.SaveTokens;
            options.SignOutPath = options.SignOutPath.Value;
            options.SignedOutRedirectUri = options.SignedOutRedirectUri;
            options.SignInScheme = options.SignInScheme;
            options.SignOutScheme = options.SignOutScheme;           
            options.UseTokenLifetime = options.UseTokenLifetime;
        }

        public void Configure(Saml2Options options)
        {
            throw new NotImplementedException();
        }
    }
}

