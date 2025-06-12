// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents a Composite ML-DSA key.
    /// </summary>
    /// <remarks>
    ///   Developers are encouraged to program against the <see cref="CompositeMLDsa"/> base class,
    ///   rather than any specific derived class. The derived classes are intended for interop with the underlying system
    ///   cryptographic libraries.
    /// </remarks>
    [Experimental(Experimentals.PostQuantumCryptographyDiagId, UrlFormat = Experimentals.SharedUrlFormat)]
    public abstract class CompositeMLDsa : IDisposable
#if DESIGNTIMEINTERFACES
#pragma warning disable SA1001
        , IImportExportShape<CompositeMLDsa>
#pragma warning restore SA1001
#endif
    {
        private const int MaxContextLength = 255;

        private bool _disposed;

        /// <summary>
        ///   Gets a value indicating whether the current platform supports Composite ML-DSA.
        /// </summary>
        /// <value>
        ///   <see langword="true" /> if the current platform supports Composite ML-DSA; otherwise, <see langword="false" />.
        /// </value>
        public static bool IsSupported { get; } = CompositeMLDsaImplementation.SupportsAny();

        /// <summary>
        ///   Gets the specific Composite ML-DSA algorithm for this key.
        /// </summary>
        public CompositeMLDsaAlgorithm Algorithm { get; }

        /// <summary>
        ///   Initializes a new instance of the <see cref="CompositeMLDsa" /> class.
        /// </summary>
        /// <param name="algorithm">
        ///   The specific Composite ML-DSA algorithm for this key.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="algorithm"/> parameter is <see langword="null"/>.
        /// </exception>
        protected CompositeMLDsa(CompositeMLDsaAlgorithm algorithm)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            Algorithm = algorithm;
        }

        /// <summary>
        ///   Signs the specified data.
        /// </summary>
        /// <param name="data">
        ///   The data to sign.
        /// </param>
        /// <param name="context">
        ///   An optional context-specific value to limit the scope of the signature.
        ///   The default value is <see langword="null" />.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="context"/> has a length in excess of 255 bytes.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   This instance has been disposed.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <para>The instance represents only a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while signing the data.</para>
        /// </exception>
        /// <remarks>
        ///   A <see langword="null" /> context is treated as empty.
        /// </remarks>
        public byte[] SignData(byte[] data, byte[]? context = default)
        {
            ArgumentNullException.ThrowIfNull(data);

            byte[] destination = new byte[Algorithm.SignatureSizeInBytes];
            SignData(new ReadOnlySpan<byte>(data), destination.AsSpan(), new ReadOnlySpan<byte>(context));
            return destination;
        }

        /// <summary>
        ///   Signs the specified data, writing the signature into the provided buffer.
        /// </summary>
        /// <param name="data">
        ///   The data to sign.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the signature. Its length must be exactly
        ///   <see cref="CompositeMLDsaAlgorithm.SignatureSizeInBytes"/>.
        /// </param>
        /// <param name="context">
        ///   An optional context-specific value to limit the scope of the signature.
        ///   The default value is an empty buffer.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   The buffer in <paramref name="destination"/> is the incorrect length to receive the signature.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="context"/> has a <see cref="ReadOnlySpan{T}.Length"/> in excess of
        ///   255 bytes.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   This instance has been disposed.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <para>The instance represents only a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while signing the data.</para>
        /// </exception>
        public void SignData(ReadOnlySpan<byte> data, Span<byte> destination, ReadOnlySpan<byte> context = default)
        {
            int signatureSizeInBytes = Algorithm.SignatureSizeInBytes;

            if (destination.Length != signatureSizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, signatureSizeInBytes),
                    nameof(destination));
            }

            if (context.Length > MaxContextLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(context),
                    context.Length,
                    SR.Argument_SignatureContextTooLong255);
            }

            ThrowIfDisposed();

            SignDataCore(data, context, destination);
        }

        /// <summary>
        ///   When overridden in a derived class, computes the signature of the specified data and context,
        ///   writing it into the provided buffer.
        /// </summary>
        /// <param name="data">
        ///   The data to sign.
        /// </param>
        /// <param name="context">
        ///   The signature context.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the signature, which will always be the exactly correct size for the algorithm.
        /// </param>
        /// <exception cref="CryptographicException">
        ///   An error occurred while signing the data.
        /// </exception>
        protected abstract void SignDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, Span<byte> destination);

        /// <summary>
        ///   Verifies that the specified signature is valid for this key and the provided data.
        /// </summary>
        /// <param name="data">
        ///   The data to verify.
        /// </param>
        /// <param name="signature">
        ///   The signature to verify.
        /// </param>
        /// <param name="context">
        ///   The context value which was provided during signing.
        ///   The default value is <see langword="null" />.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if the signature validates the data; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> or <paramref name="signature"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="context"/> has a length in excess of 255 bytes.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   This instance has been disposed.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <para>An error occurred while verifying the data.</para>
        /// </exception>
        /// <remarks>
        ///   A <see langword="null" /> context is treated as empty.
        /// </remarks>
        public bool VerifyData(byte[] data, byte[] signature, byte[]? context = default)
        {
            ArgumentNullException.ThrowIfNull(data);
            ArgumentNullException.ThrowIfNull(signature);

            return VerifyData(new ReadOnlySpan<byte>(data), new ReadOnlySpan<byte>(signature), new ReadOnlySpan<byte>(context));
        }

        /// <summary>
        ///   Verifies that the specified signature is valid for this key and the provided data.
        /// </summary>
        /// <param name="data">
        ///   The data to verify.
        /// </param>
        /// <param name="signature">
        ///   The signature to verify.
        /// </param>
        /// <param name="context">
        ///   The context value which was provided during signing.
        ///   The default value is an empty buffer.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if the signature validates the data; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="context"/> has a <see cref="ReadOnlySpan{T}.Length"/> in excess of
        ///   255 bytes.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   This instance has been disposed.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <para>An error occurred while verifying the data.</para>
        /// </exception>
        public bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context = default)
        {
            if (context.Length > MaxContextLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(context),
                    context.Length,
                    SR.Argument_SignatureContextTooLong255);
            }

            ThrowIfDisposed();

            if (signature.Length != Algorithm.SignatureSizeInBytes)
            {
                return false;
            }

            return VerifyDataCore(data, context, signature);
        }

        /// <summary>
        ///   When overridden in a derived class, verifies the signature of the specified data and context.
        /// </summary>
        /// <param name="data">
        ///   The data to verify.
        /// </param>
        /// <param name="context">
        ///   The signature context.
        /// </param>
        /// <param name="signature">
        ///   The signature to verify.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if the signature validates the data; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred while verifying the data.
        /// </exception>
        protected abstract bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature);

        /// <summary>
        ///   Exports the public-key portion of the current key in the X.509 SubjectPublicKeyInfo format.
        /// </summary>
        /// <returns>
        ///   A byte array containing the X.509 SubjectPublicKeyInfo representation of the public-key portion of this key.
        /// </returns>
        /// <exception cref="ObjectDisposedException">
        ///   This instance has been disposed.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        public byte[] ExportSubjectPublicKeyInfo()
        {
            ThrowIfDisposed();

            throw new PlatformNotSupportedException();
        }

        /// <summary>
        ///   Imports an SLH-DSA private key from a PKCS#8 PrivateKeyInfo structure.
        /// </summary>
        /// <param name="source">
        ///   The bytes of a PKCS#8 PrivateKeyInfo structure in the ASN.1-BER encoding.
        /// </param>
        /// <returns>
        ///   The imported key.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   <para>
        ///     The contents of <paramref name="source"/> do not represent an ASN.1-BER-encoded PKCS#8 PrivateKeyInfo structure.
        ///   </para>
        ///   <para>-or-</para>
        ///   <para>
        ///     The PrivateKeyInfo value does not represent an SLH-DSA key.
        ///   </para>
        ///   <para>-or-</para>
        ///   <para>
        ///     <paramref name="source" /> contains trailing data after the ASN.1 structure.
        ///   </para>
        ///   <para>-or-</para>
        ///   <para>
        ///     The algorithm-specific import failed.
        ///   </para>
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support SLH-DSA. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports SLH-DSA.
        /// </exception>
        public static SlhDsa ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
        {
            ThrowIfInvalidLength(source);
            ThrowIfNotSupported();
        }

        /// <summary>
        ///   Releases all resources used by the <see cref="CompositeMLDsa"/> class.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                Dispose(true);
                GC.SuppressFinalize(this);
            }
        }

        /// <summary>
        ///   Called by the <see cref="Dispose()" /> method to release the managed and unmanaged
        ///   resources used by the current instance of the <see cref="CompositeMLDsa"/> class.
        /// </summary>
        /// <param name="disposing">
        ///   <see langword="true" /> to release managed and unmanaged resources;
        ///   <see langword="false" /> to release only unmanaged resources.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
        }

        private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, typeof(MLDsa));
    }
}
