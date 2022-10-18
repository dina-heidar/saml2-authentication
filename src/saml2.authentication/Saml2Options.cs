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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MetadataBuilder.Schema.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Saml.MetadataBuilder;
using static Saml2Core.Saml2Constants;

namespace Saml2Core
{
    public class Saml2Options : RemoteAuthenticationOptions
    {
        private CookieBuilder _nonceCookieBuilder;
        volatile private Saml2SecurityTokenHandler _defaultHandler;
        private TokenValidationParameters _tokenValidationParameters = new TokenValidationParameters();

        public Saml2Options()
        {
            //schemes
            ForwardChallenge = AuthenticationScheme;
            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            SignOutScheme = AuthenticationScheme;
            AuthenticationScheme = Saml2Defaults.AuthenticationScheme;

            //paths
            SignOutPath = new PathString("/saml2-signout");
            ArtifactResolutionPath = new PathString("/saml2-artifact");
            SignedOutRedirectUri = "/";
            CallbackPath = new PathString("/saml2-signin");
            DefaultRedirectUrl = new PathString("/");

            //saml request
            RequireHttpsMetadata = true;
            //RequestedAuthnContext =
            ForceAuthn = true;
            NameId = new NameId
            {
                Format = NameIDFormats.Unspecified,
                SpNameQualifier =null,
                NameQualifier = null,
                SpProvidedId = null,
                Value = EntityId
            };
            IsPassive = false;
            AssertionConsumerServiceIndex = 0;
            AuthenticationMethod = Saml2AuthenticationBehaviour.RedirectGet;
            ResponseProtocolBinding = Saml2ResponseProtocolBinding.FormPost;
            SigningCertificateHashAlgorithmName = HashAlgorithmName.SHA256;

            //responses
            VerifySignatureOnly = true;
            WantAssertionsSigned = false;
            RequireMessageSigned = false;

            //logout
            LogoutMethod = Saml2LogoutBehaviour.RedirectGet;
            LogoutChannel = Saml2LogoutChannel.FrontChannel;

            //authenticationSendMethod =>  redirect(get), post ==> front-channel only
            //ProtocolBinding = post,  artifact
            ////(contains ProtocolBinding which tells the Idp how to respond, must corelate with 
            /// previously provided assertionconsumerUrl and index)
            //authenticationMethodResponseBinding => post, artifact


            //logoutSendMethod => redirect(get),post, artifact, soap ==> front-channel OR back-channel       
            //logoutMethodResponseBinding => redirect(get),post, artifact, soap



            //events
            Events = new Saml2Events();

            //metadata
            //TODO add all the metadata creation requirements here
            DefaultMetadataFolderLocation = "wwwroot";
            DefaultMetadataFileName = "Metadata";
            CreateMetadataFile = false;

            //cookie
            Saml2CoreCookieName = Saml2Defaults.AuthenticationScheme;
            Saml2CoreCookieLifetime = TimeSpan.FromMinutes(10);

            //_nonceCookieBuilder = new Saml2NonceCookieBuilder(this)
            //{
            //    Name = Saml2Defaults.CookieNoncePrefix,
            //    HttpOnly = true,
            //    SameSite = SameSiteMode.None,
            //    SecurePolicy = CookieSecurePolicy.SameAsRequest,
            //    IsEssential = true,
            //    Expiration = Saml2CoreCookieLifetime
            //};

            AllowUnsolicitedLogins = false;
        }

        /// <summary>
        /// Gets or sets the artifact resolution path.
        /// </summary>
        /// <value>
        /// The artifact resolution path.
        /// The value of the artifact resolution path
        /// must be registered with the identity provider.
        /// </value>
        public PathString ArtifactResolutionPath { get; set; }
        /// <summary>
        /// Gets or sets the index of the assertion consumer service.
        /// </summary>
        /// <value>
        /// The index of the assertion consumer service.
        /// </value>
        public ushort AssertionConsumerServiceIndex { get; set; }
        /// <summary>
        /// Gets or sets the assertion consumer service URL.
        /// This will override the CallBack value.
        /// </summary>
        /// <value>
        /// The assertion consumer service URL.
        /// </value>
        public Uri AssertionConsumerServiceUrl { get; set; }
        /// <summary>
        /// Gets or sets the authentication HTTP method.
        /// </summary>
        /// <value>
        /// The authentication method. The default value is 'HTTP-Redirect'
        /// </value>
        public Saml2AuthenticationBehaviour AuthenticationMethod { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [authentication request signed].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [authentication request signed]; otherwise, <c>false</c>.
        /// </value>
        public bool AuthenticationRequestSigned { get; set; }
        /// <summary>
        /// Gets or sets the authentication scheme.
        /// </summary>
        /// <value>
        /// The authentication scheme.
        /// </value>
        public string AuthenticationScheme { get; set; }
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
        /// Gets or sets the default redirect URL. The default value is "/"
        /// This URL is used by the SP to redirect the user back to after they log out.
        /// </summary>
        /// <value>
        /// The default redirect URL.
        /// </value>
        public PathString DefaultRedirectUrl { get; set; }
        /// <summary>
        /// Gets or sets the service provider entity identifier.
        /// </summary>
        /// <value>
        /// The entityID.
        /// </value>
        public string EntityId { get; set; }
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
        /// Gets or sets a value indicating whether authentication is required.
        /// Default value is set to true
        /// </summary>
        /// <value>
        ///   <c>true</c> if [force authn]; otherwise, <c>false</c>.
        /// </value>
        public bool ForceAuthn { get; set; }
        /// <summary>
        /// Gets or sets the identity provider metadata. This can be an address or 
        /// an xml file location.
        /// </summary>
        /// <value>
        /// The identity provider metadata address or file location.
        /// </value>
        public string MetadataAddress { get; set; }
        /// <summary>
        /// Gets or sets the name identifier format. This is needed to perform logout and SLO.
        /// </summary>
        /// <value>
        /// The name identifier format.
        /// </value>
        public NameId NameId { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether this 
        /// instance is passive.
        /// There are a few common ways to re-authenticate a user with IsPassive=true. 
        /// For example, Integrated Windows Auth (Kerberos) and x509 Cert 
        /// Based Auth can both be done w/out visibly working with the user's experience.
        /// If combined with a 'ForceAuthn = true' and 'IsPassive = true' in the 'AuthnRequest',
        /// it should force the identity provider to re-authenticate the user if both
        /// conditions can be met.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is passive; otherwise, <c>false</c>.
        /// </value>
        public bool IsPassive { get; set; }
        /// <summary>
        /// Gets or sets the logout channel type.
        /// </summary>
        /// <value>
        /// The logout channel. The default value is asynchronous 'front-channel'
        /// </value>
        public Saml2LogoutChannel LogoutChannel { get; set; }

        /// <summary>
        /// Gets or sets the logout method.
        /// </summary>
        /// <value>
        /// The logout method. The default value is 'HTTP-Redirect'
        /// </value>
        public Saml2LogoutBehaviour LogoutMethod { get; set; }
        /// <summary>
        /// Gets or sets the 'max_age'. If set the 'max_age' parameter 
        /// will be sent with the authentication request. If the identity
        /// provider has not actively authenticated the user within the 
        /// length of time specified, the user will be prompted to
        /// re-authenticate. By default no max_age is specified.
        /// </summary>
        public TimeSpan? MaxAge { get; set; }
        /// <summary>
        /// Gets or sets if a metadata refresh should be attempted after 
        /// a SecurityTokenSignatureKeyNotFoundException. This allows for automatic
        /// recovery in the event of a signature key rollover. This is enabled by default.
        /// </summary>
        public bool RefreshOnIssuerKeyNotFound { get; set; } = true;
        /// <summary>
        /// Gets or sets the remote sign out path.
        /// Requests received on this path will cause 
        /// the handler to invoke SignOut using the SignOutScheme
        /// </summary>
        /// <value>
        /// The remote sign out path.
        /// </value>
        /// 
        public PathString RemoteSignOutPath { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [require HTTPS metadata].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [require HTTPS metadata]; otherwise, <c>false</c>.
        /// </value>
        public bool RequireHttpsMetadata { get; set; }
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
        /// Gets or sets the response binding from the identity provider
        /// to the service provider. The response protocol binding 
        /// can only be 'HTTP-POST' or HTTP-Artifact'. 'HTTP-Redirect'
        /// is not allowed per standard as the response will typically 
        /// exceed the URL length permitted by most user agents (browsers).
        /// </summary>
        /// <value>
        /// The default value is 'HTTP-POST'
        /// </value>
        public Saml2ResponseProtocolBinding ResponseProtocolBinding { get; set; }
        /// <summary>
        /// Gets or sets the saml2 core cookie lifetime.
        /// </summary>
        /// <value>
        /// The saml2 core cookie lifetime.
        /// </value>
        public TimeSpan Saml2CoreCookieLifetime { get; set; }
        /// <summary>
        /// Gets or sets the name of the saml2 core cookie.
        /// </summary>
        /// <value>
        /// The name of the saml2 core cookie.
        /// </value>
        public string Saml2CoreCookieName { get; set; }
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
        /// The Authentication Scheme to use with SignOut 
        /// on the SignOutPath. SignInScheme will be used if this
        /// is not set.
        /// </summary>
        public string SignOutScheme { get; set; }
        /// <summary>
        /// Gets or sets the signing certificate.
        /// If present the outgoing requests will be signed 
        /// using this certificate. The identity provider should
        /// be aware of the this public certficate.
        /// </summary>
        /// <value>
        /// The signing certificate.
        /// </value>
        public X509Certificate2 SigningCertificate { get; set; }
        /// <summary>
        /// Gets or sets the name of the signing certificate hash algorithm.
        /// </summary>
        /// <value>
        /// The name of the signing certificate hash algorithm.
        /// </value>
        public HashAlgorithmName SigningCertificateHashAlgorithmName { get; set; }
        /// <summary>
        /// Indicates if requests to the CallbackPath may also be for other components. 
        /// If enabled the handler will pass requests through that do not 
        /// contain Saml2 authentication responses. Disabling this and setting the
        /// CallbackPath to a dedicated endpoint may provide better error handling.
        /// This is disabled by default.
        /// </summary>
        public bool SkipUnrecognizedRequests { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [use token lifetime].
        /// The default value is "true"
        /// </summary>
        /// <value>
        ///   <c>true</c> if [use token lifetime]; otherwise, <c>false</c>.
        /// </value>
        public bool UseTokenLifetime { get; set; } = true;
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
        /// Gets or sets a value indicating whether [require signed assertion].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [want signed assertion]; otherwise, <c>false</c>.
        /// </value>
        public bool WantAssertionsSigned { get; set; }


        #region TODO
        
        /// <summary>
        /// Gets or sets the sign out query string. 
        /// If set, prepends this value to your Idp logout service url. Used by AD FS to supply ?wa=wsignout1.0.
        /// Should only contain the raw key value pair, not a ? or ampersands.
        /// </summary>
        /// <value>
        /// The signout query string.
        /// </value>
        public string SignOutQueryString { get; set; }

        public override void Validate()
        {
            base.Validate();

            if (MaxAge.HasValue && MaxAge.Value < TimeSpan.Zero)
            {
                throw new Saml2Exception($"The Options.MaxAge value must not be a negative TimeSpan.");
            }

            if (string.IsNullOrEmpty(EntityId))
            {
                throw new Saml2Exception("Options.EntityId must be provided");
            }

            if (!CallbackPath.HasValue)
            {
                throw new Saml2Exception("Options.CallbackPath must be provided.");
            }

            if (ConfigurationManager == null)
            {
                throw new InvalidOperationException($"Provide {nameof(MetadataAddress)}, "
                + $"{nameof(Configuration)}, or {nameof(ConfigurationManager)} to {nameof(Saml2Options)}");
            }
        }

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
        /// //TODO
        /// Configuration will be provided directly by the developer. 
        /// If provided, then Idp MetadataAddress and the Backchannel properties
        /// will not be used. This information should not 
        /// be updated during request processing.
        /// </summary>
        internal EntityDescriptor? Configuration { get; set; }
        /// <summary>
        /// Responsible for retrieving, caching, and refreshing 
        /// the configuration from metadata.
        /// If not provided, then one will be created using the 
        /// Idp MetadataAddress and Backchannel properties.
        /// </summary>
        internal IConfigurationManager<EntityDescriptor>? ConfigurationManager { get; set; }
        /// <summary>
        /// Gets or sets the saml2 core cookie.
        /// </summary>
        /// <value>
        /// The saml2 core cookie.
        /// </value>
        internal CookieBuilder Saml2CoreCookie { get; set; }
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
        /// Gets or sets the type used to secure data handled by the handler.
        /// </summary>
        internal ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default;
        /// <summary>
        /// Gets or sets the type used to secure strings used by the handler.
        /// </summary>
        internal ISecureDataFormat<string> StringDataFormat { get; set; } = default!;
        /// <summary>
        /// Gets or sets the token validation parameters.
        /// </summary>
        /// <value>
        /// The token validation parameters.
        /// </value>
        /// <exception cref="System.ArgumentNullException">TokenValidationParameters</exception>
        internal TokenValidationParameters TokenValidationParameters
        {
            get
            {
                return _tokenValidationParameters;
            }
            set
            {
                _tokenValidationParameters = value ?? throw new ArgumentNullException(nameof(TokenValidationParameters));
            }
        }

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

        #endregion
    }
}
