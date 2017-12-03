// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PgpKeyFactory.cs" company="SNH Consulting Ltd">
//   Free to use, modify and publish as you see fit. Please provide a reference to
//   the source repository if you do use it.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace PgpNetCoreLibrary
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;

    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;

    /// <summary>
    /// The PGP key factory helper class providing functionality for creating
    /// a public/private keypair.
    /// </summary>
    public static class PgpKeyFactory
    {
        /// <summary>
        /// Create master signing key.
        /// </summary>
        /// <param name="keyRingGen">
        /// Key ring generator.
        /// </param>
        /// <param name="identity">
        /// Identity of the key.
        /// </param>
        /// <param name="password">
        /// Password to protect the secret key.
        /// </param>
        /// <param name="expires">
        /// Key expiry; null means never expires.
        /// </param>
        /// <param name="encryptKeyLength">
        /// Length of the encryption key.
        /// </param>
        /// <param name="encryptGenerator">
        /// Generator for the encryption key.
        /// </param>
        /// <param name="encryptionAlgorithm">
        /// Encryption algorithm.
        /// </param>
        /// <param name="symmetricAlgorithm">
        /// Symmetric algorithm.
        /// </param>
        /// <returns>
        /// Returns the <see cref="PgpKeyRingGenerator"/> with the keyring properties
        /// thus far.
        /// </returns>
        public static PgpKeyRingGenerator CreateEncryptionSubkey(
            PgpKeyRingGenerator keyRingGen,
            string identity,
            string password,
            DateTime? expires,
            int encryptKeyLength = 2048,
            string encryptGenerator = "RSA",
            PublicKeyAlgorithmTag encryptionAlgorithm = PublicKeyAlgorithmTag.RsaEncrypt,
            SymmetricKeyAlgorithmTag symmetricAlgorithm = SymmetricKeyAlgorithmTag.Aes256)
        {
            var keyringParameters = new KeyRingParameters(encryptKeyLength, encryptGenerator)
            {
                Password = password,
                Identity = identity,
                PrivateKeyEncryptionAlgorithm = symmetricAlgorithm,
                SymmetricAlgorithms = new[]
                {
                    SymmetricKeyAlgorithmTag.Aes256,
                    SymmetricKeyAlgorithmTag.Aes192,
                    SymmetricKeyAlgorithmTag.Aes128
                },
                HashAlgorithms = new[]
                {
                    HashAlgorithmTag.Sha256,
                    HashAlgorithmTag.Sha1,
                    HashAlgorithmTag.Sha384,
                    HashAlgorithmTag.Sha512,
                    HashAlgorithmTag.Sha224,
                }
            };

            // encryption key
            var generator = GeneratorUtilities.GetKeyPairGenerator(encryptGenerator);
            generator.Init(keyringParameters.KeyParams);
            var encKeyPair = new PgpKeyPair(encryptionAlgorithm, generator.GenerateKeyPair(), DateTime.UtcNow);

            var symmetricAlgorithms = (from a in keyringParameters.SymmetricAlgorithms
                                       select (int)a).ToArray();
            var hashAlgorithms = (from a in keyringParameters.HashAlgorithms
                                  select (int)a).ToArray();

            Debug.WriteLine("Generated encryption key with ID " + encKeyPair.KeyId.ToString("X"));
            var encSubpckGen = new PgpSignatureSubpacketGenerator();
            encSubpckGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            encSubpckGen.SetPreferredSymmetricAlgorithms(false, symmetricAlgorithms);
            encSubpckGen.SetPreferredHashAlgorithms(false, hashAlgorithms);
            if (expires != null)
            {
                encSubpckGen.SetKeyExpirationTime(false, (long)((DateTime)expires - DateTime.Now).TotalSeconds);
            }

            // add encryption subkey to keyring
            keyRingGen.AddSubKey(encKeyPair, encSubpckGen.Generate(), null);
            return keyRingGen;
        }

        /// <summary>
        /// Create public/secret keyring generator.
        /// </summary>
        /// <param name="identity">
        /// The identity.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="expires">
        /// When, if ever, should the key expire? null means never.
        /// </param>
        /// <param name="signKeyLength">
        /// The sign key keypair length.
        /// </param>
        /// <param name="signGenerator">
        /// Signing key generator type.
        /// </param>
        /// <param name="signingAlgorithm">
        /// The signing algorithm.
        /// </param>
        /// <param name="encryptKeyLength">
        /// The encrypt key keypair length.
        /// </param>
        /// <param name="encryptGenerator">
        /// Encryption key generator type.
        /// </param>
        /// <param name="encryptionAlgorithm">
        /// The encryption algorithm.
        /// </param>
        /// <param name="symmetricAlgorithm">
        /// Symmetric encryption algorithm.
        /// </param>
        /// <returns>
        /// The <see cref="PgpKeyRingGenerator"/>.
        /// </returns>
        public static PgpKeyRingGenerator CreateKeyRingGenerator(
            string identity,
            string password,
            DateTime? expires,
            int signKeyLength = 2048,
            string signGenerator = "RSA",
            PublicKeyAlgorithmTag signingAlgorithm = PublicKeyAlgorithmTag.RsaSign,
            int encryptKeyLength = 2048,
            string encryptGenerator = "RSA",
            PublicKeyAlgorithmTag encryptionAlgorithm = PublicKeyAlgorithmTag.RsaEncrypt,
            SymmetricKeyAlgorithmTag symmetricAlgorithm = SymmetricKeyAlgorithmTag.Aes256)
        {
            var keyRingGen = CreateMasterSigningKey(
                identity,
                password,
                expires,
                signKeyLength,
                signGenerator,
                signingAlgorithm,
                symmetricAlgorithm);

            return CreateEncryptionSubkey(
                keyRingGen,
                identity,
                password,
                expires,
                encryptKeyLength,
                encryptGenerator,
                encryptionAlgorithm,
                symmetricAlgorithm);
        }

        /// <summary>
        /// Create master signing key.
        /// </summary>
        /// <param name="identity">
        /// Identity of the key.
        /// </param>
        /// <param name="password">
        /// Password to protect the secret key.
        /// </param>
        /// <param name="expires">
        /// Key expiry; null means never expires.
        /// </param>
        /// <param name="signKeyLength">
        /// Length of the signing key.
        /// </param>
        /// <param name="signGenerator">
        /// Generator for the signing key.
        /// </param>
        /// <param name="signingAlgorithm">
        /// Signing algorithm.
        /// </param>
        /// <param name="symmetricAlgorithm">
        /// Symmetric algorithm.
        /// </param>
        /// <returns>
        /// Returns the <see cref="PgpKeyRingGenerator"/> with the keyring properties
        /// thus far.
        /// </returns>
        public static PgpKeyRingGenerator CreateMasterSigningKey(
            string identity,
            string password,
            DateTime? expires,
            int signKeyLength = 2048,
            string signGenerator = "RSA",
            PublicKeyAlgorithmTag signingAlgorithm = PublicKeyAlgorithmTag.RsaSign,
            SymmetricKeyAlgorithmTag symmetricAlgorithm = SymmetricKeyAlgorithmTag.Aes256)
        {
            var keyringParameters = new KeyRingParameters(signKeyLength, signGenerator)
            {
                Password = password,
                Identity = identity,
                PrivateKeyEncryptionAlgorithm = symmetricAlgorithm,
                SymmetricAlgorithms = new[]
                {
                    SymmetricKeyAlgorithmTag.Aes256,
                    SymmetricKeyAlgorithmTag.Aes192,
                    SymmetricKeyAlgorithmTag.Aes128
                },
                HashAlgorithms = new[]
                {
                    HashAlgorithmTag.Sha256,
                    HashAlgorithmTag.Sha1,
                    HashAlgorithmTag.Sha384,
                    HashAlgorithmTag.Sha512,
                    HashAlgorithmTag.Sha224,
                }
            };

            // master signing key
            var generator = GeneratorUtilities.GetKeyPairGenerator(signGenerator);
            generator.Init(keyringParameters.KeyParams);
            var masterKeyPair = new PgpKeyPair(signingAlgorithm, generator.GenerateKeyPair(), DateTime.UtcNow);
            Debug.WriteLine("Generated master key with ID " + masterKeyPair.KeyId.ToString("X"));

            var symmetricAlgorithms = (from a in keyringParameters.SymmetricAlgorithms
                                       select (int)a).ToArray();
            var hashAlgorithms = (from a in keyringParameters.HashAlgorithms
                                  select (int)a).ToArray();

            var masterSubpckGen = new PgpSignatureSubpacketGenerator();
            masterSubpckGen.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
            masterSubpckGen.SetPreferredSymmetricAlgorithms(false, symmetricAlgorithms);
            masterSubpckGen.SetPreferredHashAlgorithms(false, hashAlgorithms);
            if (expires != null)
            {
                masterSubpckGen.SetKeyExpirationTime(false, (long)((DateTime)expires - DateTime.Now).TotalSeconds);
            }

            // keyring -- adding master key
            return new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                masterKeyPair,
                keyringParameters.Identity,
                keyringParameters.PrivateKeyEncryptionAlgorithm,
                keyringParameters.GetPassword(),
                true,
                masterSubpckGen.Generate(),
                null,
                new SecureRandom());
        }

        /// <summary>
        /// Export the public/private keypair.
        /// </summary>
        /// <param name="secretPath">
        /// The secret output path.
        /// </param>
        /// <param name="publicPath">
        /// The public output path.
        /// </param>
        /// <param name="publicKey">
        /// The public key.
        /// </param>
        /// <param name="privateKey">
        /// The private key.
        /// </param>
        /// <param name="identity">
        /// The identity for the key.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase for the secret key file.
        /// </param>
        /// <param name="creationDate">
        /// Date/time the key was created.
        /// </param>
        /// <param name="publicKeyAlgorithm">
        /// The public key algorithm.
        /// </param>
        /// <param name="symmetricAlgorithm">
        /// The symmetric key algorithm.
        /// </param>
        /// <param name="armor">
        /// Should the keys be written using ASCII armor?
        /// </param>
        /// <returns>
        /// The <see cref="PgpSecretKey"/>.
        /// </returns>
        public static PgpSecretKey ExportKeyPair(
            string secretPath,
            string publicPath,
            AsymmetricKeyParameter publicKey,
            AsymmetricKeyParameter privateKey,
            string identity,
            char[] passPhrase,
            DateTime creationDate,
            PublicKeyAlgorithmTag publicKeyAlgorithm = PublicKeyAlgorithmTag.RsaGeneral,
            SymmetricKeyAlgorithmTag symmetricAlgorithm = SymmetricKeyAlgorithmTag.Aes256,
            bool armor = true)
        {
            var secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                publicKeyAlgorithm,
                publicKey,
                privateKey,
                creationDate,
                identity,
                symmetricAlgorithm,
                passPhrase,
                null,
                null,
                new SecureRandom());

            if (secretPath != null)
            {
                using (var secretOut = (Stream)new FileInfo(secretPath).OpenWrite())
                {
                    var secretOutputStream = secretOut;
                    if (armor)
                    {
                        secretOutputStream = new ArmoredOutputStream(secretOut);
                    }

                    secretKey.Encode(secretOutputStream);
                    secretOutputStream.Flush();

                    if (armor)
                    {
                        secretOutputStream.Dispose();
                    }
                }
            }

            if (publicPath != null)
            {
                using (var publicOut = (Stream)new FileInfo(publicPath).OpenWrite())
                {
                    var publicOutputStream = publicOut;
                    if (armor)
                    {
                        publicOutputStream = new ArmoredOutputStream(publicOut);
                    }

                    var key = secretKey.PublicKey;
                    key.Encode(publicOutputStream);
                    publicOutputStream.Flush();
                    
                    if (armor)
                    {
                        publicOutputStream.Dispose();
                    }
                }
            }

            return secretKey;
        }

        /// <summary>
        /// Generate key for the given username and password for the keyfile.
        /// specified.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="keyStoreUrl">
        /// The key store url.
        /// </param>
        /// <param name="writePublic">
        /// Flag indicating if public key should be written to file.
        /// </param>
        /// <param name="writePrivate">
        /// Flag indicating if private key should be written to file.
        /// </param>
        /// <param name="armor">
        /// Should export as ASCII armor?
        /// </param>
        /// <param name="keyLength">
        /// The key length.
        /// </param>
        /// <param name="symmetricKeyAlgorithm">
        /// The symmetric key algorithm.
        /// </param>
        /// <param name="publicKeyAlgorithm">
        /// The public key algorithm.
        /// </param>
        /// <returns>
        /// The <see cref="PgpSecretKey"/>.
        /// </returns>
        public static PgpSecretKey GenerateKey(
            string username,
            string password,
            string keyStoreUrl,
            bool writePublic = true,
            bool writePrivate = true,
            bool armor = true,
            int keyLength = 2048,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes256,
            PublicKeyAlgorithmTag publicKeyAlgorithm = PublicKeyAlgorithmTag.RsaGeneral)
        {
            var keyringParameters = GetParametersForPublicKeyAlgorithm(
                username,
                password,
                keyLength,
                symmetricKeyAlgorithm,
                publicKeyAlgorithm);

            IAsymmetricCipherKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyringParameters.KeyParams);

            var creationDate = DateTime.Now;
            var keyPair = keyPairGenerator.GenerateKeyPair();
            var pub = new PgpPublicKey(publicKeyAlgorithm, keyPair.Public, creationDate);
            var fp = string.Join(string.Empty, pub.GetFingerprint().Select(x => string.Format("{0:X2}", x)));

            return ExportKeyPair(
                writePrivate ? Path.Combine(keyStoreUrl, $"{fp}-priv.asc") : null,
                writePublic ? Path.Combine(keyStoreUrl, $"{fp}-pub.asc") : null,
                keyPair.Public,
                keyPair.Private,
                username,
                password.ToCharArray(),
                creationDate,
                publicKeyAlgorithm,
                symmetricKeyAlgorithm,
                armor);
        }

        /// <summary>
        /// Generate public/secret key ring file.
        /// </summary>
        /// <param name="identity">
        /// The identity.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="publicKeyFile">
        /// The public key file path.
        /// </param>
        /// <param name="privateKeyFile">
        /// The private key file path.
        /// </param>
        /// <param name="expires">
        /// When, if ever, should the key expire; null means never.
        /// </param>
        /// <param name="armor">
        /// Should output as ASCII armor?
        /// </param>
        /// <param name="signKeyLength">
        /// Signing keypair length.
        /// </param>
        /// <param name="signGenerator">
        /// Signing key generator type.
        /// </param>
        /// <param name="signingAlgorithm">
        /// The signing algorithm.
        /// </param>
        /// <param name="encryptKeyLength">
        /// Encryption keypair length.
        /// </param>
        /// <param name="encryptGenerator">
        /// Encryption key generator type.
        /// </param>
        /// <param name="encryptionAlgorithm">
        /// The encryption algorithm.
        /// </param>
        /// <param name="symmetricAlgorithm">
        /// The symmetric encryption algorithm.
        /// </param>
        public static void GenerateKeyRing(
            string identity,
            string password,
            string publicKeyFile,
            string privateKeyFile,
            DateTime? expires,
            bool armor = false,
            int signKeyLength = 2048,
            string signGenerator = "RSA",
            PublicKeyAlgorithmTag signingAlgorithm = PublicKeyAlgorithmTag.RsaSign,
            int encryptKeyLength = 2048,
            string encryptGenerator = "RSA",
            PublicKeyAlgorithmTag encryptionAlgorithm = PublicKeyAlgorithmTag.RsaEncrypt,
            SymmetricKeyAlgorithmTag symmetricAlgorithm = SymmetricKeyAlgorithmTag.Aes256)
        {
            var krgen = CreateKeyRingGenerator(
                identity,
                password,
                expires,
                signKeyLength,
                signGenerator,
                signingAlgorithm,
                encryptKeyLength,
                encryptGenerator,
                encryptionAlgorithm,
                symmetricAlgorithm);

            // Generate public key ring, dump to file.
            var pkr = krgen.GeneratePublicKeyRing();
            using (var pubout = (Stream)new FileStream(publicKeyFile, FileMode.Create))
            {
                Stream wrapped = pubout;
                if (armor)
                {
                    wrapped = new ArmoredOutputStream(pubout);
                }

                pkr.Encode(wrapped);
                wrapped.Flush();

                if (armor)
                {
                    wrapped.Dispose();
                }
            }

            // Generate private key, dump to file.
            var skr = krgen.GenerateSecretKeyRing();
            using (var secout = (Stream)new FileStream(privateKeyFile, FileMode.Create))
            {
                Stream wrapped = secout;
                if (armor)
                {
                    wrapped = new ArmoredOutputStream(secout);
                }

                skr.Encode(wrapped);
                wrapped.Flush();

                if (armor)
                {
                    wrapped.Dispose();
                }
            }
        }

        /// <summary>
        /// Sign public key with secret key. To access the private key from the 
        /// secret container a password needs to be provided.
        /// </summary>
        /// <param name="secretKey">
        /// The secret key containing the private key for signing the public
        /// key.
        /// </param>
        /// <param name="password">
        /// The password of the secret key.
        /// </param>
        /// <param name="keyToBeSigned">
        /// The public key to be signed.
        /// </param>
        /// <param name="certain">
        /// Flag indicating whether or not the certification is positive or just
        /// casual.
        /// </param>
        /// <returns>
        /// Returns the <see cref="PgpPublicKey"/> adorned with a signature by the
        /// private key passed in.
        /// </returns>
        public static PgpPublicKey SignPublicKey(
            PgpSecretKey secretKey,
            string password,
            PgpPublicKey keyToBeSigned,
            bool certain)
        {
            var id = keyToBeSigned.GetUserIds().Cast<string>().FirstOrDefault();

            // Extracting private key, and getting ready to create a signature.
            var privateKey = secretKey.ExtractPrivateKey(password.ToCharArray());
            var signatureGenerator = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signatureGenerator.InitSign(
                certain ? PgpSignature.PositiveCertification : PgpSignature.CasualCertification,
                privateKey);

            // Creating a stream to wrap the results of operation.
            var outputStream = new MemoryStream();
            var packetOutputStream = new BcpgOutputStream(outputStream);
            signatureGenerator.GenerateOnePassVersion(false).Encode(packetOutputStream);

            // Creating a generator.
            var subpacketSignatureGenerator = new PgpSignatureSubpacketGenerator();
            subpacketSignatureGenerator.SetSignerUserId(false, id);
            var packetVector = subpacketSignatureGenerator.Generate();
            signatureGenerator.SetHashedSubpackets(packetVector);
            packetOutputStream.Flush();

            // Returning the signed public key.
            return PgpPublicKey.AddCertification(
                keyToBeSigned,
                id,
                signatureGenerator.GenerateCertification(id, keyToBeSigned));
        }

        /// <summary>
        /// Write the <see cref="PgpPublicKey"/> to file.
        /// </summary>
        /// <param name="outputPath">
        /// Path to write the key to.
        /// </param>
        /// <param name="publicKey">
        /// The key to write.
        /// </param>
        /// <param name="armor">
        /// Should the file be written as ASCII armor?
        /// </param>
        public static void WriteKey(string outputPath, PgpPublicKey publicKey, bool armor)
        {
            using (var fs = new FileStream(outputPath, FileMode.Create))
            {
                var outputStream = (Stream)fs;
                if (armor)
                {
                    outputStream = new ArmoredOutputStream(fs);
                }

                publicKey.Encode(outputStream);
                outputStream.Flush();

                if (armor)
                {
                    outputStream.Dispose();
                }
            }
        }

        /// <summary>
        /// Get parameters for the specified public key algorithm.
        /// </summary>
        /// <param name="username">
        /// The username of the key.
        /// </param>
        /// <param name="password">
        /// The password for the private key.
        /// </param>
        /// <param name="keyLength">
        /// The key length.
        /// </param>
        /// <param name="symmetricKeyAlgorithm">
        /// The symmetric key algorithm.
        /// </param>
        /// <param name="publicKeyAlgorithm">
        /// The public key algorithm.
        /// </param>
        /// <returns>
        /// The generated <see cref="KeyRingParameters"/>.
        /// </returns>
        /// <exception cref="NotSupportedException">
        /// Thrown if the <see cref="PublicKeyAlgorithmTag"/> is not supported.
        /// </exception>
        private static KeyRingParameters GetParametersForPublicKeyAlgorithm(
            string username,
            string password,
            int keyLength,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm,
            PublicKeyAlgorithmTag publicKeyAlgorithm)
        {
            string generatorIndicator;
            if (publicKeyAlgorithm.ToString().StartsWith("rsa", StringComparison.CurrentCultureIgnoreCase))
            {
                generatorIndicator = "RSA";
            }
            else if (publicKeyAlgorithm.ToString().StartsWith("dsa", StringComparison.CurrentCultureIgnoreCase))
            {
                generatorIndicator = "DSA";
            }
            else if (publicKeyAlgorithm.ToString().StartsWith("elg", StringComparison.CurrentCultureIgnoreCase))
            {
                generatorIndicator = "ELGAMAL";
            }
            else
            {
                throw new NotSupportedException($"Public key algorithm not supported: {publicKeyAlgorithm.ToString()}");
            }

            var keyringParameters = new KeyRingParameters(keyLength, generatorIndicator)
            {
                Password = password,
                Identity = username,
                PrivateKeyEncryptionAlgorithm = symmetricKeyAlgorithm,
                SymmetricAlgorithms = new[]
                {
                    SymmetricKeyAlgorithmTag.Aes256,
                    SymmetricKeyAlgorithmTag.Aes192,
                    SymmetricKeyAlgorithmTag.Aes128
                },
                HashAlgorithms = new[]
                {
                    HashAlgorithmTag.Sha256,
                    HashAlgorithmTag.Sha1,
                    HashAlgorithmTag.Sha384,
                    HashAlgorithmTag.Sha512,
                    HashAlgorithmTag.Sha224,
                }
            };
            return keyringParameters;
        }

        /// <summary>
        /// The key ring parameters.
        /// </summary>
        public class KeyRingParameters
        {
            /// <summary>
            /// Initialises a new instance of the <see cref="KeyRingParameters"/> class.
            /// </summary>
            /// <param name="keyLength">
            /// The keypair length.
            /// </param>
            /// <param name="type">
            /// Key generation type.
            /// </param>
            public KeyRingParameters(int keyLength = 1024, string type = "RSA")
            {
                if (type == "RSA")
                {
                    this.KeyParams = new RsaKeyGenerationParameters(
                        BigInteger.ValueOf(0x10001),
                        new SecureRandom(),
                        keyLength,
                        80);
                }
                else if (type == "DSA")
                {
                    var pg = new DsaParametersGenerator();
                    pg.Init(keyLength, 80, new SecureRandom());
                    var dsaParam = pg.GenerateParameters();
                    this.KeyParams = new DsaKeyGenerationParameters(new SecureRandom(), dsaParam);
                }
                else if (type == "ELGAMAL")
                {
                    var epg = new ElGamalParametersGenerator();
                    epg.Init(keyLength, 20, new SecureRandom());
                    var elgamalParams = epg.GenerateParameters();
                    this.KeyParams = new ElGamalKeyGenerationParameters(new SecureRandom(), elgamalParams);
                }
                else
                {
                    throw new NotSupportedException($"Unsupport key generation type: {type}");
                }
            }

            /// <summary>
            /// Gets or sets the hash algorithms.
            /// </summary>
            public HashAlgorithmTag[] HashAlgorithms { get; set; }

            /// <summary>
            /// Gets or sets the identity.
            /// </summary>
            public string Identity { get; set; }

            /// <summary>
            /// Gets or sets the RSA parameters.
            /// </summary>
            public KeyGenerationParameters KeyParams { get; set; }

            /// <summary>
            /// Gets or sets the password.
            /// </summary>
            public string Password { get; set; }

            /// <summary>
            /// Gets or sets the private key encryption algorithm.
            /// </summary>
            public SymmetricKeyAlgorithmTag PrivateKeyEncryptionAlgorithm { get; set; }

            /// <summary>
            /// Gets or sets the symmetric algorithms.
            /// </summary>
            public SymmetricKeyAlgorithmTag[] SymmetricAlgorithms { get; set; }

            /// <summary>
            /// Get the password character array.
            /// </summary>
            /// <returns>
            /// The password <see cref="char"/> array.
            /// </returns>
            public char[] GetPassword()
            {
                return this.Password.ToCharArray();
            }
        }
    }
}