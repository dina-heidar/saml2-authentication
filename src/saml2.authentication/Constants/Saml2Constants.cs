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

namespace Saml2Core
{
    public class Saml2Constants
    {
        public static class Parameters
        {
            public const string SamlRequest = "SAMLRequest";
            public const string RelayState = "RelayState";
            public const string SigAlg = "SigAlg";
            public const string Signature = "Signature";
            public const string SamlResponse = "SAMLResponse";
        }
        public static class ResponseTypes
        {
            public const string AuthnResponse = "Response";
            public const string LogoutResponse = "LogoutResponse";
        }
        public static class Saml2ClaimTypes
        {
            public const string Namespace = "http://saml2Core/";
            public const string SessionIndex = $"{Namespace}sid";
        }
        public static class Tracing
        {
            public static readonly string Basic = Saml2Core.Tracing.TraceNames.Basic;
            public static readonly string Stores = Saml2Core.Tracing.TraceNames.Store;
            public static readonly string Cache = Saml2Core.Tracing.TraceNames.Cache;
            public static readonly string Validation = Saml2Core.Tracing.TraceNames.Validation;
            public static readonly string Services = Saml2Core.Tracing.TraceNames.Services;
            public static readonly string ServiceVersion = Saml2Core.Tracing.ServiceVersion;
        }
    }
}
