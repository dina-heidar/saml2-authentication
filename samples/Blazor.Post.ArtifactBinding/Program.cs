using Blazor.Post.ArtifactBinding.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Saml2Authentication;
using System.Security.Cryptography.X509Certificates;
using X509StoreFinder;

namespace Blazor.Post.ArtifactBinding;

public class Program
{
    public static void Main(string[] args)
    {

        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor();
        builder.Services.AddSingleton<WeatherForecastService>();

        var environment = builder.Environment;

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
            options.CreateMetadataFile = true;

            //must match with metadata file
            options.EntityId = "dev.govalerts.la.gov";
            options.RequireMessageSigned = false;
            options.WantAssertionsSigned = true;
            options.AuthenticationRequestSigned = true;

            //signin
            options.AuthenticationMethod = Saml2AuthenticationBehaviour.FormPost; //front channel
            options.RequestedAuthnContext = RequestedAuthnContextTypes.FormsAuthentication();
            options.ResponseProtocolBinding = Saml2ResponseProtocolBinding.Artifact; //send back artifact
            options.AssertionConsumerServiceUrl = new Uri("https://localhost:5001/saml2-artifact");

            //logout
            options.LogoutMethod = Saml2LogoutBehaviour.FormPost;
            options.LogoutRequestSigned = true;
            options.SignOutPath = new PathString("/signedout");

            options.ValidateArtifact = true;
            options.ValidIssuers = new string[] { "dinah.la.gov" };
            //options.AssertionConsumerServiceIndex = 2;
            options.CallbackPath = new PathString("/saml2-artifact");

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
                X509.LocalMachine.My.FindBySerialNumber.Find("[Serial number of certificate]", true, true);
            }
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

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseStaticFiles();

        app.UseRouting();

        app.MapBlazorHub();
        app.MapFallbackToPage("/_Host");

        app.Run();
    }
}
