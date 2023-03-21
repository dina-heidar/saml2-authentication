using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Mvc.Post.ArtifactBinding.Controllers;

[Authorize]
public class AccountController : Controller
{
    private readonly ILogger<AccountController> logger;

    public AccountController(ILogger<AccountController> logger)
    {
        this.logger = logger;
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public ActionResult ExternalLogin(string provider, string returnUrl)
    {
        // Request a redirect to the external login provider.
        if (returnUrl == null || Url.IsLocalUrl(returnUrl))
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };

            //add the following if you are using asp.identity,
            //signInManager uses the item 'LoginProviderKey'
            properties.Items["LoginProviderKey"] = provider;
            return Challenge(properties, provider);
        }
        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    [AllowAnonymous]
    [Route("Account/ExternalLoginCallback")]
    public IActionResult ExternalLoginCallback()
    {
        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public async Task Logout()
    {
        var result = await HttpContext.AuthenticateAsync();
        var properties = result.Properties;
        var provider = properties.Items[".AuthScheme"];
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(provider, properties);
    }
}
