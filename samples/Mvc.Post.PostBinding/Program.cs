using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Saml.MetadataBuilder;
using Saml.MetadataBuilder.Constants;
using Saml2Core;
using Saml2Core.Metadata;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Mvc.Post.PostBinding;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var environment = builder.Environment;

        // Add services to the container.
        builder.Services.AddControllersWithViews();

        builder.Services.AddAuthentication(sharedOptions =>
        {
            sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            sharedOptions.DefaultChallengeScheme = Saml2Defaults.AuthenticationScheme;
        })
        .AddSaml2(options =>
        {
            options.AuthenticationScheme = Saml2Defaults.AuthenticationScheme;
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.MetadataAddress = "https://adfs2.la.gov/federationmetadata/2007-06/federationmetadata.xml";
            options.ForceAuthn = true;
            options.VerifySignatureOnly = false;

            //must match with metadata file
            options.EntityId = "dev.govalerts.la.gov";
            options.RequireMessageSigned = false;
            options.WantAssertionsSigned = true;
            options.AuthenticationRequestSigned = true;

            //signin
            options.AuthenticationMethod = Saml2AuthenticationBehaviour.FormPost; //front channel
            options.RequestedAuthnContext = RequestedAuthnContextTypes.FormsAuthentication();
            options.ResponseProtocolBinding = Saml2ResponseProtocolBinding.FormPost; //send back artifact            
            options.CallbackPath = new PathString("/saml2-signin");

            //logout
            options.SignOutPath = new PathString("/signedout");

            //to generate a metadata file
            //metadata creation items
            options.CreateMetadataFile = true;
            options.Metadata = new Saml2Metadata
            {
                ContactPersons = new Saml2MetadataContactPerson
                {
                    Company = "OTS",
                    ContactType = ContactEnumType.Billing,
                    EmailAddress = "dina.heidar@la.gov",
                    TelephoneNumber = "123-234-1234",
                    GivenName = "Heidar",
                    Surname = "Dina"
                },
                Organization = new Saml2MetadataOrganization
                {
                    OrganizationDisplayName = "Louisiana State Government",
                    OrganizationName = "Department of Corrections IdentityApi",
                    OrganizationURL = new Uri("https://identityAPI.doc.la.gov"),
                    Language = "en-US"
                },
                // add an sp logo to the idp sign in page 
                UiInfo = new Saml2MetadataUiInfo
                {
                    Language = "en-US",
                    DisplayName = "EPSM",
                    Description = "EPSM website",
                    InformationURL = new Uri("https://epsm.la.gov"),
                    PrivacyStatementURL = new Uri("https://epsm.la.gov/privacy"),
                    LogoHeight = "12",
                    LogoWidth = "24",
                    LogoUriValue = new Uri("https://epsm.la.gov/logo.png"),
                    KeywordValues = new[] { "set", "ready", "go" }
                }
                //service
                //attribute consumer service
                //caching
                //valid until
            };

            if (environment.IsDevelopment())
            {
                options.SigningCertificate = new X509Certificate2("../SharedCertificates/dev.govalerts.la.gov.pfx",
                     "0n3wh33L", X509KeyStorageFlags.Exportable);
                options.EncryptingCertificate = new X509Certificate2("../SharedCertificates/dev.govalerts.la.gov.pfx",
                     "0n3wh33L", X509KeyStorageFlags.Exportable);
            }
            else
            {
                //if you want to search in cert store -can be used for production
                options.SigningCertificate = options.EncryptingCertificate =
                new Cryptography.X509Certificates.Extension.X509Certificate2(
                    "[Serial number of certificate]",
                    StoreName.My,
                    StoreLocation.LocalMachine,
                    X509FindType.FindBySerialNumber, true, true);
            };
            options.Events.OnTicketReceived = context =>
            {
                return Task.FromResult(0);
            };
            options.Events.OnRemoteFailure = context =>
            {
                return Task.FromResult(0);
            };
        })
        .AddCookie();

        builder.Services.AddAuthorization();

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        app.Run();
    }
}
