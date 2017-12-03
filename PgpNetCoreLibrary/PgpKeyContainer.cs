// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PgpKeyContainer.cs" company="SNH Consulting Ltd">
//   Free to use, modify and publish as you see fit. Please provide a reference to
//   the source repository if you do use it.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace PgpNetCoreLibrary
{
    using System;
    using System.IO;

    using Org.BouncyCastle.Bcpg.OpenPgp;

    /// <summary>
    /// The PGP key container.
    /// </summary>
    public class PgpKeyContainer
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PgpKeyContainer"/> class.
        /// </summary>
        /// <param name="publicKeyPath">
        /// The public key path.
        /// </param>
        /// <param name="privateKeyPath">
        /// The private key path.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase.
        /// </param>
        /// <exception cref="ArgumentException">
        /// Throws a <see cref="ArgumentException"/> if the public or private
        /// key does not exist in the specified location or if the passphrase
        /// is null or whitespace.
        /// </exception>
        public PgpKeyContainer(string publicKeyPath, string privateKeyPath, string passPhrase)
        {
            if (!File.Exists(publicKeyPath))
            {
                throw new ArgumentException("Public key file not found", nameof(publicKeyPath));
            }

            if (!File.Exists(privateKeyPath))
            {
                throw new ArgumentException("Private key file not found", nameof(privateKeyPath));
            }

            if (string.IsNullOrEmpty(passPhrase))
            {
                throw new ArgumentException("passPhrase is null or empty.", nameof(passPhrase));
            }

            this.PublicKey = this.ReadPublicKey(publicKeyPath, true);
            this.SecretKey = this.ReadSecretKey(privateKeyPath, true);
            this.PrivateKey = this.ReadPrivateKey(passPhrase);
        }

        /// <summary>
        /// Gets the private key.
        /// </summary>
        public PgpPrivateKey PrivateKey { get; private set; }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        public PgpPublicKey PublicKey { get; private set; }

        /// <summary>
        /// Gets the secret key.
        /// </summary>
        public PgpSecretKey SecretKey { get; private set; }

        /// <summary>
        /// Reads the private key from the <see cref="PgpSecretKey"/> container.
        /// </summary>
        /// <param name="passPhrase">
        /// The pass phrase protecting the key.
        /// </param>
        /// <returns>
        /// The <see cref="PgpPrivateKey"/>.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Throws a <see cref="ArgumentException"/> if the key could not be
        /// extracted.
        /// </exception>
        private PgpPrivateKey ReadPrivateKey(string passPhrase)
        {
            var privateKey = this.SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());
            if (privateKey != null)
            {
                return privateKey;
            }

            throw new ArgumentException("No private key found in secret key.");
        }

        /// <summary>
        /// Reads the public key from the keyring.
        /// </summary>
        /// <param name="publicKeyPath">
        /// The public key path.
        /// </param>
        /// <param name="encryption">
        /// Looking for the encryption key?
        /// </param>
        /// <returns>
        /// The <see cref="PgpPublicKey"/>.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Throws a <see cref="ArgumentException"/> if no key is available.
        /// </exception>
        private PgpPublicKey ReadPublicKey(string publicKeyPath, bool encryption)
        {
            using (Stream keyringStream = File.OpenRead(publicKeyPath))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyringStream))
            {
                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                foreach (PgpPublicKeyRing keyRing in publicKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        if (key != null && key.IsEncryptionKey == encryption)
                        {
                            return key;
                        }
                    }
                }
            }

            throw new ArgumentException("No encryption key found in public key ring.");
        }

        /// <summary>
        /// The read secret key.
        /// </summary>
        /// <param name="privateKeyPath">
        /// The private key path.
        /// </param>
        /// <param name="signing">
        /// Is it the signing key we are looking for?
        /// </param>
        /// <returns>
        /// The <see cref="PgpSecretKey"/>.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Throws a <see cref="ArgumentException"/> if no key is available.
        /// </exception>
        private PgpSecretKey ReadSecretKey(string privateKeyPath, bool signing)
        {
            using (Stream keyringStream = File.OpenRead(privateKeyPath))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyringStream))
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                    {
                        if (key != null && key.IsSigningKey == signing)
                        {
                            return key;
                        }
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }
    }
}