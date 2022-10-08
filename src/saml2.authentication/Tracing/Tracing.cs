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
using System.Diagnostics;

namespace Saml2Core
{
    internal static class Tracing
    {
        private static readonly Version AssemblyVersion = typeof(Tracing).Assembly.GetName().Version;

        /// <summary>
        /// Base ActivitySource
        /// </summary>
        public static ActivitySource BasicActivitySource { get; } = new(
            TraceNames.Basic, ServiceVersion);

        /// <summary>
        /// Store ActivitySource
        /// </summary>
        public static ActivitySource StoreActivitySource { get; } = new(
            TraceNames.Store, ServiceVersion);

        /// <summary>
        /// Cache ActivitySource
        /// </summary>
        public static ActivitySource CacheActivitySource { get; } = new(
            TraceNames.Cache, ServiceVersion);

        /// <summary>
        /// Cache ActivitySource
        /// </summary>
        public static ActivitySource ServiceActivitySource { get; } = new(
            TraceNames.Services, ServiceVersion);

        /// <summary>
        /// Detailed validation ActivitySource
        /// </summary>
        public static ActivitySource ValidationActivitySource { get; } = new(
            TraceNames.Validation, ServiceVersion);

        /// <summary>
        /// Service version
        /// </summary>
        public static string ServiceVersion => $"{AssemblyVersion.Major}.{AssemblyVersion.Minor}.{AssemblyVersion.Build}";

        public static class TraceNames
        {
            /// <summary>
            /// Service name for base traces
            /// </summary>
            public static string Basic => "Saml2Core";

            /// <summary>
            /// Service name for store traces
            /// </summary>
            public static string Store => Basic + ".Stores";

            /// <summary>
            /// Service name for caching traces
            /// </summary>
            public static string Cache => Basic + ".Cache";

            /// <summary>
            /// Service name for caching traces
            /// </summary>
            public static string Services => Basic + ".Services";

            /// <summary>
            /// Service name for detailed validation traces
            /// </summary>
            public static string Validation => Basic + ".Validation";
        }
    }
}
