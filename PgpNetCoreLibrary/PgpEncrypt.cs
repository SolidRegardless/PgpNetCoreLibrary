// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PgpEncrypt.cs" company="SNH Consulting Ltd">
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
    /// PGP encryption helper methods.
    /// </summary>
    public static class PgpEncrypt
    {
        /// <summary>
        /// Encrypt and sign the file.
        /// </summary>
        /// <param name="inputFile">
        /// Input path of the file to encrypt.
        /// </param>
        /// <param name="outputFile">
        /// Output path of the encrypted file.
        /// </param>
        /// <param name="publicKeyFile">
        /// Path to the public key file.
        /// </param>
        /// <param name="privateKeyFile">
        /// Path to the secret key file containing the private key.
        /// </param>
        /// <param name="passPhrase">
        /// The passphrase protecting the secret file.
        /// </param>
        /// <param name="symmetricKeyAlgorithm">
        /// Symmetric encryption algorithm.
        /// </param>
        /// <param name="armor">
        /// Should the encrypted file be written as ASCII armor?
        /// </param>
        /// <param name="integrityProtect">
        /// Integrity protect?
        /// </param>
        /// <param name="compressionAlgorithm">
        /// Compression algorithm to use.
        /// </param>
        /// <exception cref="FileNotFoundException">
        /// Throws a <see cref="FileNotFoundException"/> if the input, public
        /// key or secret key files do not exist.
        /// </exception>
        public static void EncryptAndSignFile(
            string inputFile,
            string outputFile,
            string publicKeyFile,
            string privateKeyFile,
            string passPhrase,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes256,
            bool armor = true,
            bool integrityProtect = true,
            CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Zip)
        {
            var encryptionKeys = new PgpKeyContainer(publicKeyFile, privateKeyFile, passPhrase);

            VerifyEncryptionParameters(inputFile, publicKeyFile, privateKeyFile, passPhrase, encryptionKeys);

            using (Stream outputStream = File.Create(outputFile))
            {
                if (armor)
                {
                    using (var armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputEncrypted(
                            inputFile,
                            armoredOutputStream,
                            encryptionKeys,
                            integrityProtect,
                            symmetricKeyAlgorithm,
                            compressionAlgorithm);
                    }
                }
                else
                {
                    OutputEncrypted(
                        inputFile,
                        outputStream,
                        encryptionKeys,
                        integrityProtect,
                        symmetricKeyAlgorithm,
                        compressionAlgorithm);
                }
            }
        }

        /// <summary>
        /// Encrypt a file as specified by the input file path.
        /// </summary>
        /// <param name="inputFile">
        /// The file to encrypt.
        /// </param>
        /// <param name="outputFile">
        /// The file to write the encrypted content to.
        /// </param>
        /// <param name="publicKeyFile">
        /// The path to the public key file to use for encryption.
        /// </param>
        /// <param name="symmetricKeyAlgorithm">
        /// Encryption algorithm.
        /// </param>
        /// <param name="armor">
        /// Should the encrypted file be written using ASCII armor?
        /// </param>
        /// <param name="withIntegrityCheck">
        /// Should the integrity be verified?
        /// </param>
        /// <param name="compressionAlgorithm">
        /// Compression algorithm to use.
        /// </param>
        public static void EncryptFile(
            string inputFile,
            string outputFile,
            string publicKeyFile,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes256,
            bool armor = true,
            bool withIntegrityCheck = true,
            CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Zip)
        {
            try
            {
                using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
                {
                    PgpPublicKey encKey = PgpKeyHelper.ReadPublicKey(publicKeyStream);

                    using (var memoryStream = new MemoryStream())
                    {
                        var compressedDataGenerator = new PgpCompressedDataGenerator(compressionAlgorithm);
                        WriteFileToLiteralData(
                            compressedDataGenerator.Open(memoryStream),
                            PgpLiteralData.Binary,
                            new FileInfo(inputFile));

                        compressedDataGenerator.Close();
                        var encryptedDataGenerator = new PgpEncryptedDataGenerator(
                            symmetricKeyAlgorithm,
                            withIntegrityCheck,
                            new SecureRandom());

                        encryptedDataGenerator.AddMethod(encKey);
                        var bytes = memoryStream.ToArray();

                        using (Stream outputStream = File.Create(outputFile))
                        {
                            if (armor)
                            {
                                using (var armoredStream = new ArmoredOutputStream(outputStream))
                                using (var encryptedStream = encryptedDataGenerator.Open(armoredStream, bytes.Length))
                                {
                                    encryptedStream.Write(bytes, 0, bytes.Length);
                                }
                            }
                            else
                            {
                                using (
                                    Stream encryptedOutputStream = encryptedDataGenerator.Open(
                                        outputStream,
                                        bytes.Length))
                                {
                                    encryptedOutputStream.Write(bytes, 0, bytes.Length);
                                }
                            }
                        }
                    }
                }
            }
            catch (PgpException exception)
            {
                PgpCommon.DumpException(exception);
                throw;
            }
        }

        /// <summary>
        /// Chain the compressed output.
        /// </summary>
        /// <param name="encryptedOut">
        /// The encrypted output.
        /// </param>
        /// <param name="compressionAlgorithm">
        /// The compression algorithm to use.
        /// </param>
        /// <returns>
        /// The encrypted data <see cref="Stream"/>.
        /// </returns>
        private static Stream ChainCompressedOut(Stream encryptedOut, CompressionAlgorithmTag compressionAlgorithm)
        {
            var compressedDataGenerator = new PgpCompressedDataGenerator(compressionAlgorithm);
            return compressedDataGenerator.Open(encryptedOut);
        }

        /// <summary>
        /// Chain the encrypted output.
        /// </summary>
        /// <param name="outputStream">
        /// The output stream.
        /// </param>
        /// <param name="encryptionKeys">
        /// The encryption keys.
        /// </param>
        /// <param name="integrityProtected">
        /// Integrity protect?
        /// </param>
        /// <param name="symmetricKeyAlgorithm">
        /// Symmetric algorithm.
        /// </param>
        /// <returns>
        /// The <see cref="Stream"/>.
        /// </returns>
        private static Stream ChainEncryptedOut(
            Stream outputStream,
            PgpKeyContainer encryptionKeys,
            bool integrityProtected,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes128)
        {
            var encryptedDataGenerator = new PgpEncryptedDataGenerator(
                symmetricKeyAlgorithm,
                integrityProtected,
                new SecureRandom());
            encryptedDataGenerator.AddMethod(encryptionKeys.PublicKey);
            return encryptedDataGenerator.Open(outputStream, new byte[PgpCommon.BufferSize]);
        }

        /// <summary>
        /// Chain the literal output.
        /// </summary>
        /// <param name="compressedOut">
        /// The compressed output.
        /// </param>
        /// <param name="file">
        /// The file to read from.
        /// </param>
        /// <returns>
        /// The chained <see cref="Stream"/> output.
        /// </returns>
        private static Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            var pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(
                compressedOut,
                PgpLiteralData.Binary,
                file.Name,
                file.Length,
                file.LastWriteTime);
        }

        /// <summary>
        /// Initialise the signature generator.
        /// </summary>
        /// <param name="compressedOutputStream">
        /// The compressed output.
        /// </param>
        /// <param name="encryptionKeys">
        /// The PGP encryption key container.
        /// </param>
        /// <returns>
        /// The <see cref="PgpSignatureGenerator"/>.
        /// </returns>
        private static PgpSignatureGenerator InitSignatureGenerator(
            Stream compressedOutputStream,
            PgpKeyContainer encryptionKeys)
        {
            const bool IsCritical = false;
            const bool IsNested = false;

            var tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
            var pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha256);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, encryptionKeys.PrivateKey);

            foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                var subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(IsCritical, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                break;
            }

            pgpSignatureGenerator.GenerateOnePassVersion(IsNested).Encode(compressedOutputStream);
            return pgpSignatureGenerator;
        }

        /// <summary>
        /// Output encrypted data stream
        /// </summary>
        /// <param name="inputFile">
        /// The input file.
        /// </param>
        /// <param name="outputStream">
        /// The output stream.
        /// </param>
        /// <param name="encryptionKeys">
        /// The encryption keys.
        /// </param>
        /// <param name="integrityProtected">
        /// Integrity protect?
        /// </param>
        /// <param name="symmetricKeyAlgorithm">
        /// Symmetric algorithm.
        /// </param>
        /// <param name="compressionAlgorithm">
        /// Compression algorithm.
        /// </param>
        private static void OutputEncrypted(
            string inputFile,
            Stream outputStream,
            PgpKeyContainer encryptionKeys,
            bool integrityProtected,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes128,
            CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Zip)
        {
            using (
                var encryptedOut = ChainEncryptedOut(
                    outputStream,
                    encryptionKeys,
                    integrityProtected,
                    symmetricKeyAlgorithm))
            using (var compressedOut = ChainCompressedOut(encryptedOut, compressionAlgorithm))
            {
                var unencryptedFileInfo = new FileInfo(inputFile);
                var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);

                using (var literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                using (var inputFileStream = unencryptedFileInfo.OpenRead())
                {
                    WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                }
            }
        }

        /// <summary>
        /// Pipe file contents.
        /// </summary>
        /// <param name="fileInfo">
        /// The file.
        /// </param>
        /// <param name="outputStream">
        /// The output stream.
        /// </param>
        /// <param name="bufferSize">
        /// The buffer size.
        /// </param>
        private static void PipeFileContents(FileInfo fileInfo, Stream outputStream, long bufferSize)
        {
            using (var inputStream = fileInfo.OpenRead())
            {
                var buf = new byte[bufferSize];

                int length;
                while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
                {
                    outputStream.Write(buf, 0, length);
                }

                outputStream.Dispose();
            }
        }

        /// <summary>
        /// Verify encryption parameters.
        /// </summary>
        /// <param name="inputFile">
        /// The input file.
        /// </param>
        /// <param name="publicKeyFile">
        /// The public key file.
        /// </param>
        /// <param name="privateKeyFile">
        /// The private key file.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase.
        /// </param>
        /// <param name="encryptionKeys">
        /// The encryption keys.
        /// </param>
        /// <exception cref="FileNotFoundException">
        /// Thrown if any of the paths specified are invalid.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// Thrown if the encryption keys or passphrase are null.
        /// </exception>
        private static void VerifyEncryptionParameters(
            string inputFile,
            string publicKeyFile,
            string privateKeyFile,
            string passPhrase,
            PgpKeyContainer encryptionKeys)
        {
            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException(string.Format("Input file [{0}] does not exist.", inputFile));
            }

            if (!File.Exists(publicKeyFile))
            {
                throw new FileNotFoundException(string.Format("Public Key file [{0}] does not exist.", publicKeyFile));
            }

            if (!File.Exists(privateKeyFile))
            {
                throw new FileNotFoundException(string.Format("Private Key file [{0}] does not exist.", privateKeyFile));
            }

            if (string.IsNullOrEmpty(passPhrase))
            {
                throw new ArgumentNullException(nameof(passPhrase));
            }

            if (encryptionKeys == null)
            {
                throw new ArgumentNullException(nameof(encryptionKeys));
            }
        }

        /// <summary>
        /// Write file to literal data.
        /// </summary>
        /// <param name="output">
        /// The output stream.
        /// </param>
        /// <param name="fileType">
        /// The file type.
        /// </param>
        /// <param name="file">
        /// The file to read,
        /// </param>
        private static void WriteFileToLiteralData(Stream output, char fileType, FileInfo file)
        {
            var data = new PgpLiteralDataGenerator();
            using (var stream = data.Open(output, fileType, file.Name, file.Length, file.LastWriteTime))
            {
                PipeFileContents(file, stream, file.Length);
            }
        }

        /// <summary>
        /// Write output and sign.
        /// </summary>
        /// <param name="compressedOutputStream">
        /// The compressed output.
        /// </param>
        /// <param name="literalOutputStream">
        /// The literal output.
        /// </param>
        /// <param name="inputFileStream">
        /// The input file.
        /// </param>
        /// <param name="signatureGenerator">
        /// The signature generator.
        /// </param>
        private static void WriteOutputAndSign(
            Stream compressedOutputStream,
            Stream literalOutputStream,
            Stream inputFileStream,
            PgpSignatureGenerator signatureGenerator)
        {
            int length;
            var buffer = new byte[PgpCommon.BufferSize];
            while ((length = inputFileStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                literalOutputStream.Write(buffer, 0, length);
                signatureGenerator.Update(buffer, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOutputStream);
        }
    }
}