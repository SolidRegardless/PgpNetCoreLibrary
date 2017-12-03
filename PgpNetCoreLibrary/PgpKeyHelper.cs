// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PgpKeyHelper.cs" company="SNH Consulting Ltd">
//   Free to use, modify and publish as you see fit. Please provide a reference to
//   the source repository if you do use it.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace PgpNetCoreLibrary
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;

    using Org.BouncyCastle.Bcpg.OpenPgp;

    /// <summary>
    /// Helper class proving some basic key manipulation routines.
    /// </summary>
    public static class PgpKeyHelper
    {
        /// <summary>
        /// Search a secret keyring collection for a secret key corresponding to
        /// key identifier if it exists.
        /// </summary>
        /// <param name="secretKeyring">
        /// The PGP secret keyring bundle.
        /// </param>
        /// <param name="keyId">
        /// The key identifier to search for.
        /// </param>
        /// <param name="pass">
        /// The passphrase to use for accessing the secret keyring.
        /// </param>
        /// <returns>
        /// The found <see cref="PgpPrivateKey"/>; null otherwise.
        /// </returns>
        public static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle secretKeyring, long keyId, char[] pass)
        {
            return secretKeyring?.GetSecretKey(keyId)?.ExtractPrivateKey(pass);
        }

        /// <summary>
        /// Gets the fingerprint from the <see cref="PgpPublicKey"/> contained within the
        /// <see cref="PgpSecretKey"/> object.
        /// </summary>
        /// <param name="key">
        /// The <see cref="PgpSecretKey"/> encapsulating the <see cref="PgpPublicKey"/>.
        /// </param>
        /// <returns>
        /// The <see cref="string"/> fingerprint.
        /// </returns>
        public static string GetFingerprintFromKey(PgpSecretKey key)
        {
            return GetFingerprintFromKey(key.PublicKey);
        }

        /// <summary>
        /// Gets the fingerprint from the <see cref="PgpPublicKey"/>.
        /// </summary>
        /// <param name="key">
        /// The <see cref="PgpPublicKey"/>.
        /// </param>
        /// <returns>
        /// The <see cref="string"/> fingerprint.
        /// </returns>
        public static string GetFingerprintFromKey(PgpPublicKey key)
        {
            return string.Join(string.Empty, key.GetFingerprint().Select(x => x.ToString("X2")));
        }

        /// <summary>
        /// Gets the first public key from the <see cref="PgpPublicKeyRingBundle"/>.
        /// </summary>
        /// <param name="publicKeyRingBundle">
        /// The <see cref="PgpPublicKeyRingBundle"/> to extract the key from.
        /// </param>
        /// <returns>
        /// Returns the <see cref="PgpPublicKey"/>.
        /// </returns>
        public static PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            return (from PgpPublicKeyRing keyring in publicKeyRingBundle.GetKeyRings()
                    select keyring.GetPublicKeys().Cast<PgpPublicKey>().FirstOrDefault(k => k.IsEncryptionKey))
                .FirstOrDefault(key => key != null);
        }

        /// <summary>
        /// Gets the first secret key from the <see cref="PgpSecretKeyRingBundle"/>.
        /// </summary>
        /// <param name="secretKeyRingBundle">
        /// The <see cref="PgpSecretKeyRingBundle"/> to extract the key from.
        /// </param>
        /// <returns>
        /// Returns the <see cref="PgpSecretKey"/>.
        /// </returns>
        public static PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            return (from PgpSecretKeyRing keyring in secretKeyRingBundle.GetKeyRings()
                    select keyring.GetSecretKeys().Cast<PgpSecretKey>().FirstOrDefault()).FirstOrDefault(
                        key => key != null);
        }

        /// <summary>
        /// Simple routine that opens a keyring file and loads the first available key
        /// suitable for encryption. 
        /// </summary>
        /// <param name="inputStream">
        /// Input stream to read the keys from.
        /// </param>
        /// <returns>
        /// Returns the <see cref="PgpPublicKey"/>; null if not found.
        /// </returns>
        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            var publicKeyRing = new PgpPublicKeyRingBundle(inputStream);
            foreach (PgpPublicKeyRing keyRing in publicKeyRing.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Reads a <see cref="PgpPublicKey"/> from the raw string.
        /// </summary>
        /// <param name="raw">
        /// The raw string.
        /// </param>
        /// <returns>
        /// The <see cref="PgpPublicKey"/>.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// No key found.
        /// </exception>
        public static PgpPublicKey ReadPublicKey(string raw)
        {
            var byteArray = Encoding.ASCII.GetBytes(raw);
            var stream = new MemoryStream(byteArray);

            using (var inputStream = PgpUtilities.GetDecoderStream(stream))
            {
                var publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                var foundKey = GetFirstPublicKey(publicKeyRingBundle);
                if (foundKey != null)
                {
                    return foundKey;
                }
            }

            throw new ArgumentException("No encryption key found in public key ring.");
        }

        /// <summary>
        /// Simple routine that opens a key ring file and loads the first available key 
        /// suitable for signature generation.
        /// </summary>
        /// <param name="keyringStream">
        /// Input stream to read the secret key ring collection from.
        /// </param>
        /// <returns>
        /// Returns the first available <see cref="PgpSecretKey"/>.
        /// </returns>
        public static PgpSecretKey ReadSecretKey(Stream keyringStream)
        {
            var secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyringStream));

            foreach (PgpSecretKeyRing secretKeyRing in secretKeyRingBundle.GetKeyRings())
            {
                foreach (PgpSecretKey secretKey in secretKeyRing.GetSecretKeys())
                {
                    if (secretKey.IsSigningKey)
                    {
                        return secretKey;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }

        /// <summary>
        /// Reads the first secret key from the keyring file.
        /// </summary>
        /// <param name="fileName">
        /// The keyring file path.
        /// </param>
        /// <returns>
        /// Returns the first available <see cref="PgpSecretKey"/>.
        /// </returns>
        public static PgpSecretKey ReadSecretKey(string fileName)
        {
            using (Stream keyIn = File.OpenRead(fileName))
            {
                return ReadSecretKey(keyIn);
            }
        }

        /// <summary>
        /// Reads a <see cref="PgpSecretKey"/> from the raw string.
        /// </summary>
        /// <param name="raw">
        /// The raw string.
        /// </param>
        /// <returns>
        /// The <see cref="PgpSecretKey"/>.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// No key found.
        /// </exception>
        public static PgpSecretKey ReadSecretKeyFromRaw(string raw)
        {
            var byteArray = Encoding.ASCII.GetBytes(raw);
            var stream = new MemoryStream(byteArray);

            using (var inputStream = PgpUtilities.GetDecoderStream(stream))
            {
                var secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                var foundKey = GetFirstSecretKey(secretKeyRingBundle);
                if (foundKey != null)
                {
                    return foundKey;
                }
            }

            throw new ArgumentException("No encryption key found in public key ring.");
        }
    }
}