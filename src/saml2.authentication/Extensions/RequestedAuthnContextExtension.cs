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

using Saml.MetadataBuilder.Constants;

namespace Saml2Core
{

    public static class RequestedAuthnContextTypes
    {
        /// <summary>
        /// Sets authentication as forms the authentication.
        /// </summary>
        /// <param name="comparisonType">Type of the comparison.</param>
        /// <returns></returns>
        public static RequestedAuthenticationContext FormsAuthentication(string comparisonType = "exact")
        {
            return new RequestedAuthenticationContext
            {
                ComparisonType = comparisonType,
                AuthnContextRefTypes = new[] { AuthnContextRefTypes.UserNameAndPassword }
            };
        }

        /// <summary>
        /// Sets authentication windows authentication (WIA).
        /// </summary>
        /// <param name="comparisonType">Type of the comparison.</param>
        /// <returns></returns>
        public static RequestedAuthenticationContext WindowsAuthentication(string comparisonType = "exact")
        {
            return new RequestedAuthenticationContext
            {
                ComparisonType = comparisonType,
                AuthnContextRefTypes = new[] { AuthnContextRefTypes.IntegratedWindowsAuthentication }
            };
        }

        /// <summary>
        /// Customs the specified authn context reference types.
        /// </summary>
        /// <param name="authnContextRefTypes">The authn context reference types.</param>
        /// <param name="comparisonTypes">The comparison types.</param>
        /// <returns></returns>
        public static RequestedAuthenticationContext Custom(string authnContextRefTypes,
            string comparisonTypes = "exact")
        {
            return new RequestedAuthenticationContext
            {
                ComparisonType = comparisonTypes,
                AuthnContextRefTypes = new[] { authnContextRefTypes }
            };
        }
    }
}

