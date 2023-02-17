
using System;
using System.Linq;
using Microsoft.AspNetCore.Http;

namespace Saml2Core.Helpers
{
    /// <summary>
    /// 
    /// </summary>
    public static class HttpExtensions
    {
        /// <summary>
        /// Deletes all request identifier cookies.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="request">The request.</param>
        /// <param name="samlCookieName">Name of the saml cookie.</param>
        public static void DeleteAllSaml2RequestCookies(this HttpResponse response, HttpRequest request, string samlCookieName)
        {
            var cookies = request.Cookies;
            foreach (var cookie in cookies.Where(c => c.Key.StartsWith(samlCookieName)))
            {
                response.Cookies.Append(cookie.Key, "", new CookieOptions() { Expires = DateTime.Now.AddDays(-1) });
                response.Cookies.Delete(cookie.Key);
            }
        }
    }
}
