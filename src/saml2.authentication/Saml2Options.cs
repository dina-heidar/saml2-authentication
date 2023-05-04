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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Saml2Metadata;
using static Saml2Authentication.Saml2Constants;

namespace Saml2Authentication
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Authentication.RemoteAuthenticationOptions" />
    public class Saml2Options : RemoteAuthenticationOptions
    {
        volatile private Saml2SecurityTokenHandler _defaultHandler;
        private TokenValidationParameters _tokenValidationParameters = new TokenValidationParameters();

        public Saml2Options()
        {
            //schemes
            ForwardChallenge = AuthenticationScheme;
            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            AuthenticationScheme = Saml2Defaults.AuthenticationScheme;

            //paths
            SignOutPath = new PathString("/saml2-signout");
            SignedOutRedirectUri = "/";
            CallbackPath = new PathString("/saml2-signin");
            DefaultRedirectUrl = new PathString("/");

            //saml request
            RequireHttpsMetadata = true;
            ForceAuthn = false;
            NameIdPolicy = new NameIdPolicy
            {
                Format = NameIDFormats.Unspecified,
                SpNameQualifier = null,
                AllowCreate = true
            };
            IsPassive = false;
            AuthenticationMethod = Saml2AuthenticationBehaviour.RedirectGet;
            ResponseProtocolBinding = Saml2ResponseProtocolBinding.FormPost;
            SigningCertificateHashAlgorithmName = HashAlgorithmName.SHA256;

            //responses
            VerifySignatureOnly = true;
            WantAssertionsSigned = false;
            RequireMessageSigned = false;

            //logout
            LogoutMethod = Saml2LogoutBehaviour.RedirectGet;
            LogoutRequestSigned = true;
            ResponseLogoutBinding = Saml2ResponseLogoutBinding.FormPost; //for the metadata, how the idp will send the logout response

            //events
            Events = new Saml2Events();

            //metadata
            Metadata = new Saml2MetadataXml();
            DefaultMetadataFolderLocation = "wwwroot";
            DefaultMetadataFileName = "Metadata";
            CreateMetadataFile = false;
            //ValidateMetadata = true;

            //cookie
            Saml2CookieName = Saml2Defaults.AuthenticationScheme;

            Saml2Cookie = new CookieBuilder()
            {
                Name = Saml2CookieName,
                IsEssential = CookieConsentNeeded,
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                SecurePolicy = CookieSecurePolicy.Always
            };

            AllowUnsolicitedLogins = false;
            SkipUnrecognizedRequests = true;
        }

        /// <summary>
        /// Gets or sets the index of the assertion consumer service.
        /// If this is populated, it will override the Callback, 
        /// AssertionConsumerServiceUrl and the ResponseProtocolBinding
        /// values. Only the 'AssertionConsumerServiceIndex' will be sent 
        /// for the AuthnRequest.
        /// </summary>
        /// <value>
        /// The index of the assertion consumer service.
        /// </value>
        public ushort? AssertionConsumerServiceIndex { get; set; }
        /// <summary>
        /// Gets or sets the assertion consumer service URL.
        /// This will override the CallBack value.        
        /// If the 'AssertionConsumerServiceIndex' is populated, the Callback, 
        /// AssertionConsumerServiceUrl and the ResponseProtocolBinding
        /// values will not be sent within the AuthnRequest.
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
        /// Gets or sets the cookie consent as essential or not
        /// It overrdies the Cookie policy set.
        /// This is needed when signign in. the default value is "true".
        /// </summary>
        /// <value>
        /// <c>true</c> if [cookie consent needed]; otherwise, <c>false</c>.
        /// </value>
        public bool CookieConsentNeeded { get; set; } = true;
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
        /// Gets or sets the encrypting certificate.
        /// This is used to decrypt the encrypted 
        /// assertion. Only RSA is supported.
        /// </summary>
        /// <value>
        /// The encrypting certificate.
        /// </value>
        public X509Certificate2 EncryptingCertificate { get; set; }
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
        /// Gets or sets the location of the idp single sign on service index.
        /// if null, the first SignleSignOnService location with configured 
        /// protocol binding will be used.
        /// </summary>
        /// <value>
        /// The index of the idp single sign on service.
        /// </value>
        public ushort? IdpSingleSignOnServiceLocationIndex { get; set; }
        /// <summary>
        /// Gets or sets the location of the idp single logout service index.
        /// if null, the first SingleLogoutService location with configured 
        /// protocol binding will be used.
        /// </summary>
        /// <value>
        /// The index of the idp single logout service.
        /// </value>
        public ushort? IdpSingleLogoutServiceLocationIndex { get; set; }

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
        /// Gets or sets the logout method.
        /// </summary>
        /// <value>
        /// The logout method. The default value is 'HTTP-Redirect'
        /// </value>
        public Saml2LogoutBehaviour LogoutMethod { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [logout request signed].
        /// The 'LogoutRequest' message SHOULD be signed or otherwise authenticated and integrity protected
        /// by the protocol binding used to deliver the message
        /// https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
        /// section 3.7.1
        /// </summary>
        /// <value>
        /// The default value is <c>true</c> if [logout request signed]; otherwise, <c>false</c>.
        /// </value>
        public bool LogoutRequestSigned { get; set; }

        /// <summary>
        /// Gets or sets the 'max_age'. If set the 'max_age' parameter 
        /// will be sent with the authentication request. If the identity
        /// provider has not actively authenticated the user within the 
        /// length of time specified, the user will be prompted to
        /// re-authenticate. By default no max_age is specified.
        /// </summary>
        public TimeSpan? MaxAge { get; set; }

        /// <summary>
        /// Creates the metadata file when `CreateMetadatFile=true`.
        /// </summary>
        /// <value>
        /// The metadata.
        /// </value>
        public Saml2MetadataXml Metadata { get; set; }
        /// <summary>
        /// Gets or sets the identity provider metadata. This can be an address or 
        /// an xml file location.
        /// </summary>
        /// <value>
        /// The identity provider metadata address or file location.
        /// </value>
        public string MetadataAddress { get; set; }
        /// <summary>
        /// Gets or sets the name identifier.
        /// </summary>
        /// <value>
        /// The name identifier.
        /// </value>
        internal NameId NameId { get; set; }
        /// <summary>
        /// Gets or sets the name identifier format. This is needed to perform logout and SLO.
        /// </summary>
        /// <value>
        /// The name identifier format. The default NameIDFormat is 
        /// urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
        /// </value>
        public NameIdPolicy NameIdPolicy { get; set; }
        /// <summary>
        /// Gets or sets if a metadata refresh should be attempted after 
        /// a SecurityTokenSignatureKeyNotFoundException. This allows for automatic
        /// recovery in the event of a signature key rollover. This is enabled by default.
        /// </summary>
        internal bool RefreshOnIssuerKeyNotFound { get; set; } = true;
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
        /// Gets or sets the requested authn context.
        /// </summary>
        /// <value>
        /// The requested authn context.
        /// </value>
        public RequestedAuthenticationContext RequestedAuthnContext { get; set; }
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
        /// Gets or sets the response logout binding.
        /// </summary>
        /// <value>
        /// The response logout binding.
        /// </value>
        public Saml2ResponseLogoutBinding ResponseLogoutBinding { get; set; }
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
        /// Gets or sets the name of the saml2 core cookie.
        /// </summary>
        /// <value>
        /// The name of the saml2 core cookie.
        /// </value>
        public string Saml2CookieName { get; set; }
        /// <summary>
        /// Gets or sets the remote sign out path. The default value is "/saml2-signout"
        /// This is used by the Idp to POST back to after it logs the user out of the Idp session.
        /// </summary>
        /// <value>
        /// The remote sign out path.
        /// </value>
        public PathString SignOutPath { get; set; }

        /// <summary>
        /// Gets or sets the signing certificate.
        /// If present the outgoing requests will be signed 
        /// using this certificate. The identity provider should
        /// be aware of the this public certficate.
        /// Both RSA and ECDSA is suported.
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
        /// Indicates if requests to the CallbackPath may also be for other components. 
        /// If enabled the handler will pass requests through that do not 
        /// contain Saml2 authentication responses. Disabling this and setting the
        /// CallbackPath to a dedicated endpoint may provide better error handling.
        /// This is disabled by default.
        /// </summary>
        internal bool SkipUnrecognizedRequests { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [use token lifetime].
        /// The default value is "true"
        /// </summary>
        /// <value>
        ///   <c>true</c> if [use token lifetime]; otherwise, <c>false</c>.
        /// </value>
        public bool UseTokenLifetime { get; set; } = true;
        /// <summary>
        /// Gets or sets a value indicating whether [validate artifact].
        /// This will validate the incoming saml artifact value if HTTP-Artifact 
        /// was set as protocol binding.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [validate artifact]; otherwise, <c>false</c>.
        /// </value>
        public bool ValidateArtifact { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether [validate audience].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [validate audience]; otherwise, <c>false</c>.
        /// </value>
        public bool ValidateAudience { get; set; } = true;
        /// <summary>
        /// Gets or sets the valid audiences.If not set
        /// the service provider entityId will be used
        /// </summary>
        /// <value>
        /// The valid audiences.
        /// </value>
        public IEnumerable<string> ValidAudiences { get; set; } = new List<string>();
        /// <summary>
        /// Gets or sets a value indicating whether [validate issuer].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [validate issuer]; otherwise, <c>false</c>.
        /// </value>
        public bool ValidateIssuer { get; set; } = true;
        /// <summary>
        /// Gets or sets the valid issuers. If not set
        /// the entityId from the Idp will be used
        /// </summary>
        /// <value>
        /// The valid issuers.
        /// </value>
        public IEnumerable<string> ValidIssuers { get; set; } = new List<string>();
        /// <summary>
        /// Gets or sets the bool responsible for signature validation
        /// true to verify the signature only; 
        /// false to verify both the signature and 
        /// certificate (it'll do the chain verification to make sure the certificate is valid).
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
        internal string SignOutQueryString { get; set; }

        /// <summary>
        /// Check that the options are valid.  Should throw an exception if things are not ok.
        /// </summary>
        /// <exception cref="Saml2Authentication.Saml2Exception">
        /// The Options.MaxAge value must not be a negative TimeSpan.
        /// or
        /// Options.EntityId must be provided
        /// or
        /// Options.CallbackPath must be provided.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">Provide {nameof(MetadataAddress)}, "
        ///                 + $"{nameof(Configuration)}, or {nameof(ConfigurationManager)} to {nameof(Saml2Options)}</exception>
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
        /// https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf section 4.1.5 Unsolicited Responses
        /// </summary>
        /// <value>
        ///   <c>true</c> if [allow unsolicited logins]; otherwise, <c>false</c>.
        /// </value>
        internal bool AllowUnsolicitedLogins { get; set; }
        /// <summary>
        /// Configuration will be provided directly by the developer.
        /// If provided, then Idp MetadataAddress and the Backchannel properties
        /// will not be used. This information should not
        /// be updated during request processing.
        /// </summary>
        /// <value>
        /// The configuration.
        /// </value>
        internal EntityDescriptor Configuration { get; set; }
        /// <summary>
        /// Responsible for retrieving, caching, and refreshing
        /// the configuration from metadata.
        /// If not provided, then one will be created using the
        /// Idp MetadataAddress and Backchannel properties.
        /// </summary>
        /// <value>
        /// The configuration manager.
        /// </value>
        internal IConfigurationManager<EntityDescriptor> ConfigurationManager { get; set; }
        /// <summary>
        /// Gets or sets the saml2 core cookie.
        /// </summary>
        /// <value>
        /// The saml2 core cookie.
        /// </value>
        internal CookieBuilder Saml2Cookie { get; set; }
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
