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
using MetadataBuilder.Schema.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens.Saml2;
using Saml2Core.Events;

namespace Saml2Core
{
    public class Saml2Options : RemoteAuthenticationOptions
    {
        private CookieBuilder _nonceCookieBuilder;
        volatile private Saml2SecurityTokenHandler _defaultHandler;

        public Saml2Options()
        {
            ForwardChallenge = AuthenticationScheme;
            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            SignOutScheme = AuthenticationScheme;
            AuthenticationScheme = Saml2Defaults.AuthenticationScheme;
            SignOutPath = new PathString("/signedout");
            SignedOutRedirectUri = "/";
            CallbackPath = new PathString("/saml2-signin");
            DefaultRedirectUrl = new PathString("/");

            //saml request
            RequireHttpsMetadata = true;
            ForceAuthn = true;
            NameIDType = new NameIDType();
            IsPassive = false;
            VerifySignatureOnly = true;

            //events
            Events = new Saml2Events();

            //metadata
            DefaultMetadataFolderLocation = "wwwroot";
            DefaultMetadataFileName = "Metadata";
            CreateMetadataFile = false;

            //saml reponse
            WantAssertionsSigned = false;
            RequireMessageSigned = false;

            //cookie
            Saml2CoreCookieName = Saml2Defaults.AuthenticationScheme;
            Saml2CoreCookieLifetime = TimeSpan.FromMinutes(10);

            _nonceCookieBuilder = new Saml2NonceCookieBuilder(this)
            {
                Name = Saml2Defaults.CookieNoncePrefix,
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                IsEssential = true,               
                Expiration = Saml2CoreCookieLifetime,
                
            };

            AllowUnsolicitedLogins = false;
        }
        
        /// <summary>
        /// Gets or sets the name of the saml2 core cookie.
        /// </summary>
        /// <value>
        /// The name of the saml2 core cookie.
        /// </value>
        public string Saml2CoreCookieName { get; set; }
        /// <summary>
        /// Gets or sets the requested authn context.
        /// </summary>
        /// <value>
        /// The requested authn context.
        /// </value>
        public RequestAuthn RequestAuthn { get; set; }
        /// <summary>
        /// Gets or sets the bool responsible for signature validation
        /// true to verify the signature only; false to verify both the signature and certificate.
        /// The default value is set to "true".
        /// </summary>
        /// <value>
        /// <c>false</c> if [verify signature only]; otherwise, <c>true</c>.
        /// </value>

        public bool VerifySignatureOnly { get; set; }
        /// <summary>
        /// Gets or sets the cookie consent as essential or not
        /// It overrdies the Cookie policy set.
        /// This is needed when signign in. the default value is "true".
        /// </summary>
        /// <value>
        /// <c>true</c> if [cookie consent needed]; otherwise, <c>false</c>.
        /// </value>
        public bool CookieConsentNeeded { get; set; } = true;

        /// <summary>
        /// Gets or sets the default redirect URL. The default value is "/"
        /// This URL is used by the SP to redirect the user back to after they log out.
        /// </summary>
        /// <value>
        /// The default redirect URL.
        /// </value>
        public PathString DefaultRedirectUrl { get; set; }
        /// <summary>
        /// Gets or sets the remote sign out path.
        /// Requests received on this path will cause 
        /// the handler to invoke SignOut using the SignOutScheme
        /// </summary>
        /// <value>
        /// The remote sign out path.
        /// </value>
        public PathString RemoteSignOutPath { get; set; }
        /// <summary>
        /// Gets or sets the remote sign out path. The default value is "/signedout"
        /// This is used by the Idp to POST back to after it logs the user out of the Idp session.
        /// </summary>
        /// <value>
        /// The remote sign out path.
        /// </value>
        public PathString SignOutPath { get; set; }
        /// <summary>
        /// Gets or sets the signed out redirect URI.
        /// This URI can be out of the application's domain. 
        /// By default it points to the root.
        /// </summary>
        /// <value>
        /// The signed out redirect URI.
        /// </value>
        public string SignedOutRedirectUri { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [use token lifetime].
        /// The default value is "true"
        /// </summary>
        /// <value>
        ///   <c>true</c> if [use token lifetime]; otherwise, <c>false</c>.
        /// </value>
        public bool UseTokenLifetime { get; set; } = true;
        /// <summary>
        /// Gets or sets a value indicating whether [create metadata file]. 
        /// The defalut is set to "false".
        /// If set to "true" and there is no exisiting metadata file
        /// in that location then the middleware will 
        /// create a meetadata.xml file.         
        /// This can be accessed at "host"/metadata.xml
        /// </summary>
        /// <value>
        ///   <c>true</c> if [create metadata file]; otherwise, <c>false</c>.
        /// </value>
        public bool CreateMetadataFile { get; set; }

        /// <summary>
        /// Gets or sets the default metadata file location.
        /// The default value of this folder is "wwwroot".
        /// </summary>
        /// <value>
        /// The default metadata file location. The 
        /// </value>
        public string DefaultMetadataFolderLocation { get; set; }
        /// <summary>
        /// Gets or sets the default name of the metadata file.
        /// The default value of this folder is "Metadata.xml".
        /// </summary>
        /// <value>
        /// The default name of the metadata file.
        /// </value>
        public string DefaultMetadataFileName { get; set; }

        /// <summary>
        /// Gets or sets a bool value indicating that 
        /// the Identity Provider must have the message signed. 
        /// This needs to be set on the Idp side.
        /// </summary>
        /// <value>
        /// <c>true</c> if [require message signed]; otherwise, <c>false</c>.
        /// </value>
        public bool RequireMessageSigned { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [require signed assertion].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [want signed assertion]; otherwise, <c>false</c>.
        /// </value>
        public bool WantAssertionsSigned { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether authentication is required.
        /// Default value is set to true
        /// </summary>
        /// <value>
        ///   <c>true</c> if [force authn]; otherwise, <c>false</c>.
        /// </value>
        public bool ForceAuthn { get; set; }

        /// <summary>
        /// Gets or sets the idp metadata. This can be an address or 
        /// an xml file location.
        /// </summary>
        /// <value>
        /// The idp metadata address or file location.
        /// </value>
        public string MetadataAddress { get; set; }
        /// <summary>
        /// Gets or sets the saml2 core cookie lifetime.
        /// </summary>
        /// <value>
        /// The saml2 core cookie lifetime.
        /// </value>
        public TimeSpan Saml2CoreCookieLifetime { get; set; }

        /// <summary>
        /// Gets or sets the authentication scheme.
        /// </summary>
        /// <value>
        /// The authentication scheme.
        /// </value>
        public string AuthenticationScheme { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [require HTTPS metadata].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [require HTTPS metadata]; otherwise, <c>false</c>.
        /// </value>
        public bool RequireHttpsMetadata { get; set; }
        /// <summary>
        /// Gets or sets the events.
        /// This can be later expanded to have custom events.
        /// </summary>
        /// <value>
        /// The events.
        /// </value>
        public new Saml2Events Events
        {
            get => (Saml2Events)base.Events;
            set => base.Events = value;
        }
        /// <summary>
        /// The Authentication Scheme to use with SignOut 
        /// on the SignOutPath. SignInScheme will be used if this
        /// is not set.
        /// </summary>
        public string? SignOutScheme { get; set; }


        #region TODO
        /// <summary>
        /// Gets or sets a value indicating whether this 
        /// instance is passive.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is passive; otherwise, <c>false</c>.
        /// </value>
        public bool IsPassive { get; set; }
        /// <summary>
        /// Gets or sets the name identifier format.
        /// </summary>
        /// <value>
        /// The name identifier format.
        /// </value>
        public NameIDType NameIDType { get; set; }
        /// <summary>
        /// Gets or sets the sign out query string. 
        /// If set, prepends this value to your Idp logout service url. Used by AD FS to supply ?wa=wsignout1.0.
        /// Should only contain the raw key value pair, not a ? or ampersands.
        /// </summary>
        /// <value>
        /// The signout query string.
        /// </value>
        public string SignOutQueryString { get; set; }

        public string DynamicProvider { get; set; }
        #endregion

        #region Bindings
        /// <summary>
        /// Gets or sets the assertion consumer service protocol binding. The default is HTTP_Post.
        /// </summary>
        /// <value>
        /// The assertion consumer service protocol binding.
        /// </value>
        //internal string AssertionConsumerServiceProtocolBinding { get; set; } = ProtocolBindings.HTTP_Post;
        /// <summary>
        /// Gets or sets the single logout service protocol binding. The default is HTTP_Redirect.
        /// </summary>
        /// <value>
        /// The single logout service protocol binding.
        /// </value>
        //internal string SingleLogoutServiceProtocolBinding { get; set; } = ProtocolBindings.HTTP_Post;

        #endregion

        #region Internals
        /// <summary>
        /// The Saml protocol allows the user to initiate logins without contacting the application for a Challenge first.
        /// However, that flow is susceptible to XSRF and other attacks so it is disabled here by default.
        /// This will later be expanded.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [allow unsolicited logins]; otherwise, <c>false</c>.
        /// </value>
        internal bool AllowUnsolicitedLogins { get; set; }
        /// <summary>
        /// Gets or sets the saml2 core cookie.
        /// </summary>
        /// <value>
        /// The saml2 core cookie.
        /// </value>
        internal CookieBuilder Saml2CoreCookie { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance has certificate.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance has certificate; otherwise, <c>false</c>.
        /// </value>
        //internal bool hasCertificate { get; set; }
        /// <summary>
        /// Gets or sets the saml2 security token handler.
        /// </summary>
        /// <value>
        /// The saml2 p security token handler.
        /// </value>
        internal Saml2SecurityTokenHandler Saml2SecurityTokenHandler
        {
            get
            {
                // Capture in a local variable to prevent race conditions. Reads and writes
                // of references are atomic so there is no need for a lock.
                var value = _defaultHandler;
                if (value == null)
                {
                    // Set the saved value, but don't trust it - still use a local var for the return.
                    _defaultHandler = value = new Saml2SecurityTokenHandler();
                }

                return value;
            }
            set
            {
                _defaultHandler = value;
            }
        }
        /// <summary>
        /// Gets or sets the state data format.
        /// </summary>
        /// <value>
        /// The state data format.
        /// </value>
        internal ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }


        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <seealso cref="Microsoft.AspNetCore.Authentication.Internal.RequestPathBaseCookieBuilder" />
        private sealed class Saml2NonceCookieBuilder : RequestPathBaseCookieBuilder
        {
            private readonly Saml2Options _options;

            public Saml2NonceCookieBuilder(Saml2Options options)
            {
                _options = options;
            }

            protected override string AdditionalPath => _options.CallbackPath;

            public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
            {
                var cookieOptions = base.Build(context, expiresFrom);

                if (!Expiration.HasValue || !cookieOptions.Expires.HasValue)
                {
                    //TODO check how many mins per standard
                    cookieOptions.Expires = DateTimeOffset.Now.AddMinutes(10);
                }
                return cookieOptions;
            }
        }
    }

   

}
