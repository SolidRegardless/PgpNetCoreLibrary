// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PgpCommon.cs" company="SNH Consulting Ltd">
//   Free to use, modify and publish as you see fit. Please provide a reference to
//   the source repository if you do use it.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace PgpNetCoreLibrary
{
    using System;
    using System.IO;
    using System.Text;

    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Utilities.IO;

    /// <summary>
    /// Common PGP constants and helper methods.
    /// </summary>
    public static class PgpCommon
    {
        /// <summary>
        /// The buffer size.
        /// </summary>
        /// <remarks>
        /// Should always be power of 2.
        /// </remarks>
        public const int BufferSize = 0x10000;

        /// <summary>
        /// Compress data object as a PGP message using the specified compression
        /// format.
        /// </summary>
        /// <param name="data">
        /// The data to compress.
        /// </param>
        /// <param name="format">
        /// The format to compress that data as.
        /// </param>
        /// <param name="armor">
        /// Compress using ASCII armor format?
        /// </param>
        /// <returns>
        /// The compressed <see cref="byte"/> array.
        /// </returns>
        public static byte[] CompressData(
            byte[] data,
            CompressionAlgorithmTag format = CompressionAlgorithmTag.Zip,
            bool armor = true)
        {
            using (var binaryStream = new MemoryStream())
            using (var armorStream = armor ? (Stream)new ArmoredOutputStream(binaryStream) : binaryStream)
            {
                var compressedDataGenerator = new PgpCompressedDataGenerator(format);
                using (var compressedStream = compressedDataGenerator.Open(armorStream, new byte[8]))
                {
                    compressedStream.Write(data, 0, data.Length);
                }

                // .NET standard 1.6 compliant
                armorStream.Dispose();
                return binaryStream.ToArray();
            }
        }

        /// <summary>
        /// Decompress previously compressed BZIP2 output encoded using ASCII
        /// armor format.
        /// </summary>
        /// <param name="data">
        /// The data to decompress.
        /// </param>
        /// <returns>
        /// The decompressed <see cref="byte"/> array.
        /// </returns>
        public static byte[] DecompressData(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                var objectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(stream));
                var compressedData = (PgpCompressedData)objectFactory.NextPgpObject();

                using (var compressedDataStream = compressedData.GetDataStream())
                {
                    var actualBytes = Streams.ReadAll(compressedDataStream);
                    return actualBytes;
                }
            }
        }

        /// <summary>
        /// Dump an exception including its inner exception if not null.
        /// </summary>
        /// <param name="exception">
        /// The <see cref="PgpException"/> to dump.
        /// </param>
        /// <returns>
        /// The <see cref="string"/> being written out.
        /// </returns>
        public static string DumpException(PgpException exception)
        {
            var stringBuilder = new StringBuilder();

            if (exception.InnerException != null)
            {
                stringBuilder.AppendLine(exception.InnerException.Message);
                stringBuilder.AppendLine(exception.InnerException.StackTrace);
            }

            stringBuilder.AppendLine(exception.Message);
            stringBuilder.AppendLine(exception.StackTrace);

            var output = stringBuilder.ToString();
            Console.Error.WriteLine(output);

            return output;
        }
    }
}