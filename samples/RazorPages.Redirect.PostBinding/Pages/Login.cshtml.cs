using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorPages.Redirect.PostBinding.Pages;

public class LoginModel : PageModel
{
    public async Task OnPost(string redirectUri)
    {
        await HttpContext.ChallengeAsync("Saml2", new AuthenticationProperties { RedirectUri = redirectUri });
    }
}
