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
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Saml2Core
{
    /// <summary>
    /// 
    /// </summary>
    public static class Saml2CoreExtensions
    {

        /// <summary>
        /// Adds the saml2 authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSaml2(this AuthenticationBuilder builder)
          => builder.AddSaml2(Saml2Defaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Adds the saml2 authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSaml2(this AuthenticationBuilder builder,
            Action<Saml2Options> configureOptions)
        => builder.AddSaml2(Saml2Defaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Adds the saml2 authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSaml2(this AuthenticationBuilder builder,
            string authenticationScheme, Action<Saml2Options> configureOptions)
         => builder.AddSaml2(authenticationScheme, Saml2Defaults.DisplayName, configureOptions);

        /// <summary>
        /// Adds the saml2 authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSaml2(this AuthenticationBuilder builder,
            string authenticationScheme, string displayName, Action<Saml2Options> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<Saml2Options>, Saml2ConfigureOptions>());
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<Saml2Options>, Saml2PostConfigureOptions>());
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ISaml2Service, Saml2Service>());
            //builder.Services.AddTransient<Saml2CookieEventHandler>();
            //builder.Services.AddSingleton<LogoutSessionManager>();
            //builder.Services.TryAddEnumerable(ServiceDescriptor.Transient<IDocumentRetriever, FileDocumentRetriever>());
            //builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IHttpContextAccessor, HttpContextAccessor>());

            return builder.AddRemoteScheme<Saml2Options, Saml2Handler>(authenticationScheme, displayName, configureOptions);

        }
    }
}
