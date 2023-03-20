using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Blazor.Artifact.PostBinding.Pages;

public class LoginModel : PageModel
{
    public async Task OnGet(string redirectUri)
    {
        await HttpContext.ChallengeAsync("Saml2", new AuthenticationProperties { RedirectUri = redirectUri });
    }
}
