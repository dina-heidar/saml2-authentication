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
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Logging;

namespace Saml2Core.Helpers
{
    public class Artifact
    {
        /// <summary>
        /// Gets or sets the type code value.
        /// Type of the artifact. This is always 0x0004
        /// </summary>
        /// <value>
        /// The type code value.
        /// </value>
        public short TypeCodeValue { get; set; }
        public string TypeCodeValueString { get; set; }
        /// <summary>
        /// Gets or sets the index of the endpoint.
        /// The issuer's artifact Resolution Service endpoint 
        /// where the artifact should be resolved
        /// </summary>
        /// <value>
        /// The index of the endpoint.
        /// </value>
        public short? EndpointIndex { get; set; }
        public string EndpointIndexString { get; set; }
        /// <summary>
        /// Gets or sets the source code identifier. 
        /// Represents the entity ID of the provider who created 
        /// this artifact. The entity ID is hashed using SHA-1, 
        /// ensuring that it's always 20 bytes in length
        /// </summary>
        /// <value>
        /// The source code identifier.
        /// </value>
        public byte[] SourceCodeId { get; set; }
        public string SourceCodeIdString { get; set; }
        /// <summary>
        /// Gets or sets the message handler.
        /// A cryptographically random value that identifies this specific artifact
        /// </summary>
        /// <value>
        /// The message handler.
        /// </value>
        public byte[] MessageHandler { get; set; }
        public string MessageHandlerString { get; set; }
    }

    internal static class ArtifactHelpers
    {
        private const int typeCodeLength = 2;
        private const int endPointLength = 2;
        private const int sourceIdLength = 20;
        private const int messageHandlerLength = 20;
        private const int artifactBytesLength = 44;

        internal static bool TryParseArtifact(string artifactStringValue)
        {
            try
            {
                GetParsedArtifact(artifactStringValue);
            }
            catch
            {
                return false;
            }

            return true;
        }

        //https://en.wikipedia.org/wiki/SAML_2.0#ArtifactResolveRequest
        internal static Artifact GetParsedArtifact(string artifactStringValue)
        {
            var artifactBytes = Convert.FromBase64String(artifactStringValue);
            if (artifactBytes.Length != artifactBytesLength)
            {
                throw new Saml2Exception($"Artifact length is {artifactBytes.Length}, it should be 44");
            }

            //typeCode is 2 bytes
            var typeCodeValue = (short)(artifactBytes[0] << 8 | artifactBytes[1]);

            //endpointIndex is 2 bytes
            var endpointIndex = (short)(artifactBytes[2] << 8 | artifactBytes[3]);

            //sourceIdBytes is 20 bytes and is hashed, we cannot hash but we can compare
            var sourceIdBytes = new byte[sourceIdLength];

            Array.Copy(artifactBytes, 4, sourceIdBytes, 0, sourceIdLength);

            //messageHandlerBytes is 20 bytes 
            var messageHandlerBytes = new byte[messageHandlerLength];
            Array.Copy(artifactBytes, 24, messageHandlerBytes, 0, messageHandlerLength);

            var typeCodeValueString = BitConverter.ToString(artifactBytes, 0, 2).Replace("-", string.Empty);
            var endpointIndexString = BitConverter.ToString(artifactBytes, 2, 2).Replace("-", string.Empty);
            var sourceIdString = BitConverter.ToString(artifactBytes, 4, 20).Replace("-", string.Empty);
            var messageHandlerString = BitConverter.ToString(artifactBytes, 24, 20).Replace("-", string.Empty);

            var artifact = new Artifact
            {
                TypeCodeValueString = typeCodeValueString,
                EndpointIndexString = endpointIndexString,
                SourceCodeIdString = sourceIdString,
                MessageHandlerString = messageHandlerString,

                TypeCodeValue = typeCodeValue,
                EndpointIndex = endpointIndex,
                SourceCodeId = sourceIdBytes,
                MessageHandler = messageHandlerBytes
            };
            return artifact;
        }

        internal static string CreateArtifact(string sourceIdValue, short endpointIndexValue)
        {
            if (string.IsNullOrEmpty(sourceIdValue))
            {
                throw new Saml2Exception($"Artifact sourceId cannot be null.");
            }
            var artifactBytes = new byte[artifactBytesLength];

            //typecode
            var typeCode = new byte[typeCodeLength];
            typeCode[0] = (byte)(Saml2Constants.Artifacts.ArtifactTypeCode >> 8);
            typeCode[1] = (byte)Saml2Constants.Artifacts.ArtifactTypeCode;

            //endpointindex
            var endpointIndex = new byte[endPointLength];
            endpointIndex[0] = (byte)(endpointIndexValue >> 8);
            endpointIndex[1] = (byte)endpointIndexValue;

            //sourceId
            var sourceIdHashed = new byte[sourceIdLength];

            var sha1 = SHA1.Create();
            sourceIdHashed = sha1.ComputeHash(Encoding.ASCII.GetBytes(sourceIdValue));

            //messagehandler
            var messageHandler = new byte[messageHandlerLength];
            var randomNumber = RandomNumberGenerator.Create();
            randomNumber.GetNonZeroBytes(messageHandler);

            //add to artifactBytes 
            typeCode.CopyTo(artifactBytes, 0);
            endpointIndex.CopyTo(artifactBytes, typeCodeLength);
            sourceIdHashed.CopyTo(artifactBytes, typeCodeLength + endPointLength);
            messageHandler.CopyTo(artifactBytes, typeCodeLength + endPointLength + sourceIdLength);

            var artifactString = Convert.ToBase64String(artifactBytes);

            return artifactString;
        }

        internal static bool IsValid(string artifactString, ushort[] ars,
            string[] validIssuers)
        {
            var artifact = GetParsedArtifact(artifactString);

            //check typeCode
            if (artifact.TypeCodeValue != 4)
            {
                LogHelper.LogWarning($"Artifact type code value was incorrect");
                return false;
            }

            //check endpoint values          
            if (!ars.Contains((ushort)artifact.EndpointIndex))
            {
                LogHelper.LogWarning($"ArtifactResolutionService Index {artifact.EndpointIndex} not found");
                return false;
            }

            //check sourceId
            var sci = artifact.SourceCodeId;
            var sha1 = SHA1.Create();

            //foreach (string idpEntityId in validIssuers)
            //{
            //    var idpEntityIdHashed = BitConverter.ToString(sha1.ComputeHash(Encoding.UTF8.GetBytes(idpEntityId)));
            //    idpEntityIdHashed = idpEntityIdHashed.Replace("-", string.Empty);

            //    if (idpEntityIdHashed == sci)
            //    {
            //        var idp = idpEntityId;
            //        break;
            //    }
            //}

            foreach (var sourceId in validIssuers)
            {
                var sourceIdHashed = new byte[sourceIdLength];
                sourceIdHashed = sha1.ComputeHash(Encoding.UTF8.GetBytes(sourceId));

                if (sci.SequenceEqual(sourceIdHashed))
                {
                    break;
                }
                return false;
            }
            return true;
        }
    }
}
