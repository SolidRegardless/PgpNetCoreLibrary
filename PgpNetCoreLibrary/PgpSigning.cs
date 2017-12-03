// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PgpSigning.cs" company="SNH Consulting Ltd">
//   Free to use, modify and publish as you see fit. Please provide a reference to
//   the source repository if you do use it.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace PgpNetCoreLibrary
{
    using System;
    using System.IO;

    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Security;

    /// <summary>
    /// PGP helper methods for providing/verifying signatures.
    /// </summary>
    public static class PgpSigning
    {
        /// <summary>
        /// Create a signature from the input file and secret key provided.
        /// </summary>
        /// <param name="inputFileName">
        /// The filename of the target for which to generate the signature
        /// for.
        /// </param>
        /// <param name="keyFileName">
        /// The secret keyfile input filename.
        /// </param>
        /// <param name="outputFileName">
        /// The filename to which the signature shall be written to.
        /// </param>
        /// <param name="pass">
        /// The password for the secret key.
        /// </param>
        /// <param name="armor">
        /// Should the signature be generated as ASCII armor?
        /// </param>
        /// <returns>
        /// The <see cref="PgpSignature"/>.
        /// </returns>
        public static PgpSignature CreateDetachedFileSignature(
            string inputFileName,
            string keyFileName,
            string outputFileName,
            char[] pass,
            bool armor)
        {
            using (Stream keyStream = File.OpenRead(keyFileName))
            using (Stream output = File.Create(outputFileName))
            {
                return CreateDetachedFileSignature(inputFileName, keyStream, output, pass, armor);
            }
        }

        /// <summary>
        /// Create a signature from the input file and secret key provided.
        /// </summary>
        /// <param name="fileName">
        /// The filename of the target for which to generate the signature
        /// for.
        /// </param>
        /// <param name="keyIn">
        /// The secret keyfile input stream.
        /// </param>
        /// <param name="signatureStream">
        /// The file to which the signature shall be written to.
        /// </param>
        /// <param name="pass">
        /// The password for the secret key.
        /// </param>
        /// <param name="armor">
        /// Should the signature be generated as ASCII armor?
        /// </param>
        /// <returns>
        /// The <see cref="PgpSignature"/>.
        /// </returns>
        public static PgpSignature CreateDetachedFileSignature(
            string fileName,
            Stream keyIn,
            Stream signatureStream,
            char[] pass,
            bool armor)
        {
            if (armor)
            {
                signatureStream = new ArmoredOutputStream(signatureStream);
            }

            var secretKey = PgpKeyHelper.ReadSecretKey(keyIn);
            var privateKey = secretKey.ExtractPrivateKey(pass);
            var signatureGenerator = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);

            signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);
            
            var packetOutputStream = new BcpgOutputStream(signatureStream);
            using (var fileInputStream = File.OpenRead(fileName))
            {
                int read;
                var buffer = new byte[PgpCommon.BufferSize];
                while ((read = fileInputStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    signatureGenerator.Update(buffer, 0, read);
                }
            }

            var signature = signatureGenerator.Generate();                                                                                  
            signature.Encode(packetOutputStream);

            if (armor)
            {
                signatureStream.Dispose();
            }

            return signature;                                           
        }

        /// <summary>
        /// Verify the signature against the file.
        /// </summary>
        /// <param name="fileName">
        /// File to validate
        /// </param>
        /// <param name="signatureStream">
        /// Signature to validate.
        /// </param>
        /// <param name="keyStream">
        /// Public key to use for signature validation.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/> flag indicating verification success; false means
        /// the signature is invalid.
        /// </returns>
        public static bool VerifyDetachedFileSignature(string fileName, Stream signatureStream, Stream keyStream)
        {
            signatureStream = PgpUtilities.GetDecoderStream(signatureStream);

            var objectFactory = new PgpObjectFactory(signatureStream);
            PgpSignatureList signatureList;
            var @object = objectFactory.NextPgpObject();
            if (@object is PgpCompressedData)
            {
                var compressedData = (PgpCompressedData)@object;
                objectFactory = new PgpObjectFactory(compressedData.GetDataStream());

                signatureList = (PgpSignatureList)objectFactory.NextPgpObject();
            }
            else
            {
                signatureList = (PgpSignatureList)@object;
            }

            var pgpPubRingCollection = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyStream));
            var signature = signatureList[0];
            var key = pgpPubRingCollection.GetPublicKey(signature.KeyId);
            signature.InitVerify(key);

            using (var fileDataStream = File.OpenRead(fileName))
            {
                int read;
                var buffer = new byte[PgpCommon.BufferSize];

                while ((read = fileDataStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    signature.Update(buffer, 0, read);
                }
            }

            if (!signature.Verify())
            {
                Console.WriteLine("signature verification failed.");
                return false;
            }

            Console.WriteLine("signature verified.");
            return true;
        }

        /// <summary>
        /// Verify the signature against the file.
        /// </summary>
        /// <param name="fileName">
        /// File to validate signature against.
        /// </param>
        /// <param name="signatureFileName">
        /// Signature file name.
        /// </param>
        /// <param name="keyFileName">
        /// Public key file name to use for signature validation.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/> flag indicating verification success; false means
        /// the signature is invalid.
        /// </returns>
        public static bool VerifyDetachedFileSignature(string fileName, string signatureFileName, string keyFileName)
        {
            using (Stream inputStream = File.OpenRead(signatureFileName), keyIn = File.OpenRead(keyFileName))
            {
                return VerifyDetachedFileSignature(fileName, inputStream, keyIn);
            }
        }

        /// <summary>
        /// Read a stream and calculate the digest for a given digest type.
        /// </summary>
        /// <param name="inputStream">
        /// Stream to read data from.
        /// </param>
        /// <param name="digestType">
        /// Digest type to calculate.
        /// </param>
        /// <returns>
        /// Returns the <see cref="byte"/> array of the digest for the given digest
        /// type. The buffer is dynamically created depending on the digest length.
        /// </returns>
        public static byte[] CreateDigest(Stream inputStream, string digestType = "SHA256")
        {
            var buffer = new byte[PgpCommon.BufferSize];
            var digest = DigestUtilities.GetDigest(digestType);

            int read;
            while ((read = inputStream.Read(buffer, 0, 8)) > 0)
            {   
                digest.BlockUpdate(buffer, 0, read);
            }

            var dout = new byte[digest.GetDigestSize()];
            digest.DoFinal(dout, 0);

            return dout;
        }
    }
}