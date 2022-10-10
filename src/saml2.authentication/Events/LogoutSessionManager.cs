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

//using System;
//using System.Collections.Generic;
//using System.Linq;

//namespace Saml2Core.Events
//{
//    internal class LogoutSessionManager
//    {
//        // yes - that needs to be thread-safe, distributed etc (it's a sample)
//        List<Session> _sessions = new List<Session>();

//        public void Add(string sub, string sid)
//        {
//            _sessions.Add(new Session { Sub = sub, Sid = sid });
//        }

//        public bool IsLoggedOut(string sub, string sid)
//        {
//            var matches = _sessions.Any(s => s.IsMatch(sub, sid));
//            return matches;
//        }

//        private class Session
//        {
//            public string Sub { get; set; }
//            public string Sid { get; set; }

//            public bool IsMatch(string sub, string sid)
//            {
//                return (Sid == sid && Sub == sub) ||
//                       (Sid == sid && Sub == null) ||
//                       (Sid == null && Sub == sub);
//            }
//        }
//    }
//}
