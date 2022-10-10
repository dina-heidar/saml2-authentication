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

//using System.Security.Claims;
//using System.Threading.Tasks;
//using Microsoft.AspNetCore.Authentication;
//using Microsoft.AspNetCore.Authentication.Cookies;
//using static Saml2Core.Saml2Constants;

//namespace Saml2Core.Events
//{
//    internal partial class Saml2Events : CookieAuthenticationEvents
//    {
//        public Saml2Events(LogoutSessionManager logoutSessions)
//        {
//            LogoutSessions = logoutSessions;
//        }

//        public LogoutSessionManager LogoutSessions { get; }

//        public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
//        {
//            if (context.Principal.Identity.IsAuthenticated)
//            {
//                var sub = context.Principal.FindFirst(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
//                var sid = context.Principal.FindFirst(c => c.Type == Saml2ClaimTypes.SessionIndex)?.Value;

//                if (LogoutSessions.IsLoggedOut(sub, sid))
//                {
//                    context.RejectPrincipal();
//                    await context.HttpContext.SignOutAsync();
//                }
//            }
//        }
//    }
//}
