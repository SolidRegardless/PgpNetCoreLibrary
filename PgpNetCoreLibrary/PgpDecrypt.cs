// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PgpDecrypt.cs" company="SNH Consulting Ltd">
//   Free to use, modify and publish as you see fit. Please provide a reference to
//   the source repository if you do use it.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace PgpNetCoreLibrary
{
    using System;
    using System.IO;

    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Utilities.IO;

    /// <summary>
    /// PGP decryption helper methods.
    /// </summary>
    public static class PgpDecrypt
    {
        /// <summary>
        /// Decrypt file and verify file signature from path.
        /// </summary>
        /// <param name="inputFile">
        /// The encrypted data path.
        /// </param>
        /// <param name="outputFile">
        /// The output path.
        /// </param>
        /// <param name="privateKeyFile">
        /// The private key path.
        /// </param>
        /// <param name="publicKeyFile">
        /// The public key path.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/> value indicating whether or not the signature in
        /// the decrypted data is valid.
        /// </returns>
        public static bool DecryptAndVerifyFile(
            string inputFile,
            string outputFile,
            string privateKeyFile,
            string publicKeyFile,
            string passPhrase)
        {
            using (var inputFileStream = new FileStream(inputFile, FileMode.Open))
            using (var privateKeyStream = new FileStream(privateKeyFile, FileMode.Open))
            using (var publicKeyStream = new FileStream(publicKeyFile, FileMode.Open))
            using (var outputFileStream = new FileStream(outputFile, FileMode.Create))
            {
                return DecryptAndVerifyStream(
                    inputFileStream,
                    outputFileStream,
                    privateKeyStream,
                    publicKeyStream,
                    passPhrase.ToCharArray());
            }
        }

        /// <summary>
        /// Decrypt file and verify file signature from stream.
        /// </summary>
        /// <param name="inputStream">
        /// The encrypted data input stream.
        /// </param>
        /// <param name="outputStream">
        /// The output stream.
        /// </param>
        /// <param name="privateKeyStream">
        /// The private key stream.
        /// </param>
        /// <param name="publicKeyStream">
        /// The public key stream.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/> value indicating whether or not the signature in
        /// the decrypted data is valid.
        /// </returns>
        public static bool DecryptAndVerifyStream(
            Stream inputStream,
            Stream outputStream,
            Stream privateKeyStream,
            Stream publicKeyStream,
            char[] passPhrase)
        {
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData encryptedData = null;
            var secretKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            var encryptedDataList = GetEncryptedDataListFromStream(inputStream);
            foreach (PgpPublicKeyEncryptedData dataObject in encryptedDataList.GetEncryptedDataObjects())
            {
                privateKey = PgpKeyHelper.FindSecretKey(secretKeyRing, dataObject.KeyId, passPhrase);
                if (privateKey == null)
                {
                    continue;
                }

                encryptedData = dataObject;
                break;
            }

            if (privateKey == null)
            {
                throw new Exception("Unable to find secret key to decrypt the message");
            }

            var valid = ProcessDecryptionMessageBlocks(encryptedData, outputStream, publicKeyStream, privateKey);
            if (encryptedData.IsIntegrityProtected() && !encryptedData.Verify())
            {
                throw new PgpException("Data is integrity protected but integrity is lost.");
            }

            return valid;
        }

        /// <summary>
        /// Decrypt a file using a private key.
        /// </summary>
        /// <param name="inputfile">
        /// The encrypted file.
        /// </param>
        /// <param name="privateKeyFile">
        /// The private key file.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase protecting the secret key.
        /// </param>
        /// <param name="outputFile">
        /// The file path to write the decrypted output to.
        /// </param>
        /// <exception cref="FileNotFoundException">
        /// Throws a <see cref="FileNotFoundException"/> if either the input or
        /// private key files do not exist.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// Throws a <see cref="ArgumentNullException"/> if the output file is
        /// invalid.
        /// </exception>
        public static void DecryptFile(string inputfile, string privateKeyFile, string passPhrase, string outputFile)
        {
            if (!File.Exists(inputfile))
            {
                throw new FileNotFoundException(string.Format("Encrypted File [{0}] not found.", inputfile));
            }

            if (!File.Exists(privateKeyFile))
            {
                throw new FileNotFoundException(string.Format("Private Key File [{0}] not found.", privateKeyFile));
            }

            if (string.IsNullOrEmpty(outputFile))
            {
                throw new ArgumentNullException(nameof(outputFile));
            }

            using (Stream inputStream = File.OpenRead(inputfile))
            using (Stream keyIn = File.OpenRead(privateKeyFile))
            {
                DecryptFileStream(inputStream, keyIn, passPhrase, outputFile);
            }
        }

        /// <summary>
        /// Decrypt a stream using the private key stream.
        /// </summary>
        /// <param name="inputStream">
        /// The stream of the encrypted file.
        /// </param>
        /// <param name="privateKeyStream">
        /// The stream of the private key file.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase protecting the secret key.
        /// </param>
        /// <param name="outputFile">
        /// The file path to write the decrypted output to.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/> flag indicating decryption success; false states
        /// decryption failed because of a data integrity check error.
        /// </returns>
        public static bool DecryptFileStream(
            Stream inputStream,
            Stream privateKeyStream,
            string passPhrase,
            string outputFile)
        {
            PgpPrivateKey privateKey = null;
            var valid = true;

            try
            {
                PgpEncryptedDataList encryptedDataList;
                PgpPublicKeyEncryptedData encryptedData = null;

                var objectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                var secretKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                var @object = objectFactory.NextPgpObject();
                if (@object is PgpEncryptedDataList)
                {
                    encryptedDataList = (PgpEncryptedDataList)@object;
                }
                else
                {
                    encryptedDataList = (PgpEncryptedDataList)objectFactory.NextPgpObject();
                }

                foreach (PgpPublicKeyEncryptedData pked in encryptedDataList.GetEncryptedDataObjects())
                {
                    privateKey = PgpKeyHelper.FindSecretKey(secretKeyRing, pked.KeyId, passPhrase.ToCharArray());

                    if (privateKey == null)
                    {
                        continue;
                    }

                    encryptedData = pked;
                    break;
                }

                if (privateKey == null)
                {
                    throw new ArgumentException("Secret key for message not found.");
                }

                PgpObjectFactory plainFact;
                using (var clear = encryptedData.GetDataStream(privateKey))
                {
                    plainFact = new PgpObjectFactory(clear);
                }

                var message = plainFact.NextPgpObject();
                if (message is PgpCompressedData)
                {
                    var data = (PgpCompressedData)message;
                    PgpObjectFactory of;

                    using (var compDataIn = data.GetDataStream())
                    {
                        of = new PgpObjectFactory(compDataIn);
                    }

                    message = of.NextPgpObject();
                    if (message is PgpOnePassSignatureList)
                    {
                        message = of.NextPgpObject();
                        var literalData = (PgpLiteralData)message;
                        using (Stream output = File.Create(outputFile))
                        {
                            var unc = literalData.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                    else
                    {
                        var literalData = (PgpLiteralData)message;
                        using (Stream output = File.Create(outputFile))
                        {
                            Stream unc = literalData.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                }
                else if (message is PgpLiteralData)
                {
                    PgpLiteralData literalData = (PgpLiteralData)message;
                    string unused = literalData.FileName;

                    using (Stream outputStream = File.Create(outputFile))
                    {
                        Stream unc = literalData.GetInputStream();
                        Streams.PipeAll(unc, outputStream);
                    }
                }
                else if (message is PgpOnePassSignatureList)
                {
                    throw new PgpException("Encrypted message contains a signed message - not literal data.");
                }
                else
                {
                    throw new PgpException("Message is not a simple encrypted file - type unknown.");
                }

                if (encryptedData.IsIntegrityProtected())
                {
                    if (!encryptedData.Verify())
                    {
                        Console.Error.WriteLine("Message failed integrity check");
                        valid = false;
                    }
                    else
                    {
                        Console.Error.WriteLine("Message integrity check passed");
                    }
                }
            }
            catch (PgpException exception)
            {
                PgpCommon.DumpException(exception);
                throw;
            }

            return valid;
        }

        /// <summary>
        /// Get the encrypted data list from the input stream.
        /// </summary>
        /// <param name="inputStream">
        /// Input stream.
        /// </param>
        /// <returns>
        /// Returns the encrypted data list.
        /// </returns>
        private static PgpEncryptedDataList GetEncryptedDataListFromStream(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            var objectFactory = new PgpObjectFactory(inputStream);
            PgpEncryptedDataList encryptedDataList;

            PgpObject pgpObject = objectFactory.NextPgpObject();
            if (pgpObject is PgpEncryptedDataList)
            {
                encryptedDataList = (PgpEncryptedDataList)pgpObject;
            }
            else
            {
                encryptedDataList = (PgpEncryptedDataList)objectFactory.NextPgpObject();
            }

            return encryptedDataList;
        }

        /// <summary>
        /// Initialise the one-pass signature from the literal block.
        /// </summary>
        /// <param name="publicKeyStream">
        /// The stream containing the public stream.
        /// </param>
        /// <param name="onePassSignatureList">
        /// One-pass signature list.
        /// </param>
        /// <param name="publicKey">
        /// Public key for validating the signature.
        /// </param>
        /// <returns>
        /// Returns the one-pass signature.
        /// </returns>
        private static PgpOnePassSignature InitOnePassSignatureFromLiteral(
            Stream publicKeyStream,
            PgpOnePassSignatureList onePassSignatureList,
            ref PgpPublicKey publicKey)
        {
            if (onePassSignatureList == null)
            {
                throw new PgpException("One pass signature not found.");
            }

            var onePassSignature = onePassSignatureList[0];
            Console.WriteLine("verifier : " + onePassSignature.KeyId.ToString("X"));

            var publicKeyringBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
            publicKey = publicKeyringBundle.GetPublicKey(onePassSignature.KeyId);
            if (publicKey == null)
            {
                throw new PgpException("No public key for signature validation");
            }

            onePassSignature.InitVerify(publicKey);
            return onePassSignature;
        }

        /// <summary>
        /// Process each message block type depending on the type.
        /// </summary>
        /// <param name="encryptedData">
        /// Encrypted data packets.
        /// </param>
        /// <param name="outputStream">
        /// Stream to write output.
        /// </param>
        /// <param name="publicKeyStream">
        /// Public key stream for validating signature.
        /// </param>
        /// <param name="privateKey">
        /// Private key for decrypting data.
        /// </param>
        /// <returns>
        /// Return true if the data is valid; false otherwise.
        /// </returns>
        private static bool ProcessDecryptionMessageBlocks(
            PgpPublicKeyEncryptedData encryptedData,
            Stream outputStream,
            Stream publicKeyStream,
            PgpPrivateKey privateKey)
        {
            var valid = true;
            PgpOnePassSignatureList onePassSignatureList = null;
            PgpOnePassSignature onePassSignature = null;
            PgpPublicKey publicKey = null;

            var clear = encryptedData.GetDataStream(privateKey);
            var plainFact = new PgpObjectFactory(clear);
            var message = plainFact.NextPgpObject();

            while (message != null)
            {
                Console.WriteLine(message.ToString());
                if (message is PgpCompressedData)
                {
                    var compressedData = (PgpCompressedData)message;
                    plainFact = new PgpObjectFactory(compressedData.GetDataStream());
                }
                else if (message is PgpLiteralData)
                {
                    onePassSignature = InitOnePassSignatureFromLiteral(
                        publicKeyStream,
                        onePassSignatureList,
                        ref publicKey);

                    ProcessDecryptionStreams(outputStream, message, onePassSignature);
                }
                else if (message is PgpOnePassSignatureList)
                {
                    onePassSignatureList = (PgpOnePassSignatureList)message;
                }
                else if (message is PgpSignatureList)
                {
                    valid = VerifyOnePassSignature(message, onePassSignature, publicKey, valid);
                }
                else
                {
                    throw new PgpException("message unknown message type.");
                }

                message = plainFact.NextPgpObject();
            }

            return valid;
        }

        /// <summary>
        /// Processes the decryption streams block by block updating the one-pass
        /// signature in the same process. 
        /// </summary>
        /// <param name="outputStream">
        /// Stream to write the output.
        /// </param>
        /// <param name="message">
        /// Message block containing the input stream.
        /// </param>
        /// <param name="onePassSignature">
        /// One-pass signature.
        /// </param>
        private static void ProcessDecryptionStreams(
            Stream outputStream,
            PgpObject message,
            PgpOnePassSignature onePassSignature)
        {
            int read;
            byte[] buffer = new byte[PgpCommon.BufferSize];

            var @in = ((PgpLiteralData)message).GetInputStream();
            while ((read = @in.Read(buffer, 0, buffer.Length)) > 0)
            {
                outputStream.Write(buffer, 0, read);
                onePassSignature.Update(buffer, 0, read);
            }
        }

        /// <summary>
        /// Verify one pass signature against signed packet.
        /// </summary>
        /// <param name="message">
        /// The message containing the signature list.
        /// </param>
        /// <param name="onePassSignature">
        /// The one pass signature.
        /// </param>
        /// <param name="publicKey">
        /// The public key for validating the signature.
        /// </param>
        /// <param name="valid">
        /// Whether the status was previously valid.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/> value indicating whether the signature was valid. If
        /// the state was previously false, false will still be returned regardless.
        /// </returns>
        /// <exception cref="PgpException">
        /// Thrown if it was not possible to verify the one pass signature.
        /// </exception>
        private static bool VerifyOnePassSignature(
            PgpObject message,
            PgpOnePassSignature onePassSignature,
            PgpPublicKey publicKey,
            bool valid)
        {
            var signatureList = (PgpSignatureList)message;
            if (onePassSignature == null)
            {
                throw new PgpException("One pass signatures not found.");
            }

            for (var signatureIndex = 0; signatureIndex < signatureList.Count; signatureIndex++)
            {
                valid = valid
                    && VerifySingleSignatueAgainstOnePass(onePassSignature, publicKey, signatureList[signatureIndex]);
            }

            return valid;
        }

        /// <summary>
        /// Verify single signature against one pass signature.
        /// </summary>
        /// <param name="onePassSignature">
        /// The one pass signature.
        /// </param>
        /// <param name="publicKey">
        /// The public key for validating the signature.
        /// </param>
        /// <param name="signature">
        /// Signature to verify.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/> value indicating whether the signature was valid.
        /// </returns>
        private static bool VerifySingleSignatueAgainstOnePass(
            PgpOnePassSignature onePassSignature,
            PgpPublicKey publicKey,
            PgpSignature signature)
        {
            bool valid;
            if (onePassSignature.Verify(signature))
            {
                var userIds = publicKey.GetUserIds();
                foreach (var userId in userIds)
                {
                    Console.WriteLine($"Signed by {userId}");
                }

                Console.WriteLine("Signature verified");
                valid = true;
            }
            else
            {
                valid = false;
            }

            return valid;
        }
    }
}