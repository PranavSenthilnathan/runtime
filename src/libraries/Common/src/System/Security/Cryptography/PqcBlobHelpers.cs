// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.CompilerServices;

using KeyBlobMagicNumber = Interop.BCrypt.KeyBlobMagicNumber;
using BCRYPT_PQDSA_KEY_BLOB = Interop.BCrypt.BCRYPT_PQDSA_KEY_BLOB;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal static class PqcBlobHelpers
    {
        internal const string BCRYPT_MLDSA_PARAMETER_SET_44 = "44";
        internal const string BCRYPT_MLDSA_PARAMETER_SET_65 = "65";
        internal const string BCRYPT_MLDSA_PARAMETER_SET_87 = "87";

        internal static string GetParameterSet(MLDsaAlgorithm algorithm)
        {
            if (algorithm == MLDsaAlgorithm.MLDsa44)
            {
                return BCRYPT_MLDSA_PARAMETER_SET_44;
            }
            else if (algorithm == MLDsaAlgorithm.MLDsa65)
            {
                return BCRYPT_MLDSA_PARAMETER_SET_65;
            }
            else if (algorithm == MLDsaAlgorithm.MLDsa87)
            {
                return BCRYPT_MLDSA_PARAMETER_SET_87;
            }

            // TODO resx
            throw new PlatformNotSupportedException();
        }

        internal static MLDsaAlgorithm GetAlgorithmFromParameterSet(ReadOnlySpan<char> parameterSet)
        {
            if (parameterSet.SequenceEqual(BCRYPT_MLDSA_PARAMETER_SET_44))
            {
                return MLDsaAlgorithm.MLDsa44;
            }
            else if (parameterSet.SequenceEqual(BCRYPT_MLDSA_PARAMETER_SET_65))
            {
                return MLDsaAlgorithm.MLDsa65;
            }
            else if (parameterSet.SequenceEqual(BCRYPT_MLDSA_PARAMETER_SET_87))
            {
                return MLDsaAlgorithm.MLDsa87;
            }

            // TODO resx
            throw new PlatformNotSupportedException();
        }

        internal delegate TResult EncodeBlobFunc<TResult>(ReadOnlySpan<byte> blob);

        internal static TResult EncodeMLDsaBlob<TResult>(
            ReadOnlySpan<char> parameterSet,
            ReadOnlySpan<byte> source,
            string blobType,
            EncodeBlobFunc<TResult> callback)
        {
            PqcParameters parameters = default;

            parameters.magic = GetMagic(blobType);
            parameters.parameterSet = parameterSet;
            parameters.source = source;

            return EncodePQDsaBlob(ref parameters, callback);

            static KeyBlobMagicNumber GetMagic(string blobType)
            {
                KeyBlobMagicNumber magic;
                switch (blobType)
                {
                    case Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PUBLIC_BLOB:
                        magic = KeyBlobMagicNumber.BCRYPT_MLDSA_PUBLIC_MAGIC;
                        break;
                    case Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_BLOB:
                        magic = KeyBlobMagicNumber.BCRYPT_MLDSA_PRIVATE_MAGIC;
                        break;
                    case Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_SEED_BLOB:
                        magic = KeyBlobMagicNumber.BCRYPT_MLDSA_PRIVATE_SEED_MAGIC;
                        break;
                    default:
                        Debug.Fail("Unknown blob type.");
                        throw new CryptographicException();
                }

                return magic;
            }
        }

        internal static ReadOnlySpan<byte> DecodeMLDsaBlob(ReadOnlySpan<byte> blob, out ReadOnlySpan<char> parameterSet, out string blobType)
        {
            PqcParameters parameters = DecodePQDsaBlob(blob);

            blobType = GetBlobType(parameters);
            parameterSet = parameters.parameterSet;
            return parameters.source;

            static string GetBlobType(PqcParameters parameters)
            {
                string blobType;
                switch (parameters.magic)
                {
                    case KeyBlobMagicNumber.BCRYPT_MLDSA_PUBLIC_MAGIC:
                        blobType = Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PUBLIC_BLOB;
                        break;
                    case KeyBlobMagicNumber.BCRYPT_MLDSA_PRIVATE_MAGIC:
                        blobType = Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_BLOB;
                        break;
                    case KeyBlobMagicNumber.BCRYPT_MLDSA_PRIVATE_SEED_MAGIC:
                        blobType = Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_SEED_BLOB;
                        break;
                    default:
                        Debug.Fail("Unknown blob type.");
                        throw new CryptographicException();
                }

                return blobType;
            }
        }

        private static TResult EncodePQDsaBlob<TResult>(
            ref PqcParameters parameters,
            EncodeBlobFunc<TResult> callback)
        {
            KeyBlobMagicNumber magic = parameters.magic;
            ReadOnlySpan<char> parameterSet = parameters.parameterSet;
            ReadOnlySpan<byte> source = parameters.source;

            int blobHeaderSize = Unsafe.SizeOf<BCRYPT_PQDSA_KEY_BLOB>();
            int parameterSetLengthWithNullTerminator = sizeof(char) * (parameterSet.Length + 1);

            int blobSize =
                blobHeaderSize +
                parameterSetLengthWithNullTerminator +      // Parameter set, '\0' terminated
                source.Length;                              // Key

            byte[] rented = CryptoPool.Rent(blobSize);
            Span<byte> blobBytes = rented.AsSpan(0, blobSize);

            try
            {
                int index = 0;

                // TODO there might be some fancy stuff we can do with generics to get strongly-typed
                // structs with buffers of compile-time known lengths (e.g. parameterSet = "44\0")

                // Write header
                ref BCRYPT_PQDSA_KEY_BLOB blobHeader = ref MemoryMarshal.AsRef<BCRYPT_PQDSA_KEY_BLOB>(blobBytes);
                blobHeader.Magic = magic;
                blobHeader.cbParameterSet = parameterSetLengthWithNullTerminator;
                blobHeader.cbKey = source.Length;
                index += blobHeaderSize;

                // Write parameter set
                Span<char> blobBodyChars = MemoryMarshal.Cast<byte, char>(blobBytes.Slice(index));
                parameterSet.CopyTo(blobBodyChars);
                blobBodyChars[parameterSet.Length] = '\0';
                index += parameterSetLengthWithNullTerminator;

                // Write key
                source.CopyTo(blobBytes.Slice(index));
                index += source.Length;

                Debug.Assert(index == blobBytes.Length);
                return callback(blobBytes);
            }
            finally
            {
                CryptoPool.Return(rented);
            }
        }

        private static PqcParameters DecodePQDsaBlob(ReadOnlySpan<byte> blobBytes)
        {
            PqcParameters blobParameters = default;

            int index = 0;

            ref readonly BCRYPT_PQDSA_KEY_BLOB blob = ref MemoryMarshal.AsRef<BCRYPT_PQDSA_KEY_BLOB>(blobBytes);
            blobParameters.magic = blob.Magic;
            int parameterSetLength = blob.cbParameterSet - 2; // Null terminator char, '\0'
            int keyLength = blob.cbKey;
            index += Unsafe.SizeOf<BCRYPT_PQDSA_KEY_BLOB>();

            blobParameters.parameterSet = MemoryMarshal.Cast<byte, char>(blobBytes.Slice(index, parameterSetLength));
            index += blob.cbParameterSet;

            blobParameters.source = blobBytes.Slice(index, keyLength);

            return blobParameters;
        }

        private ref struct PqcParameters
        {
            internal KeyBlobMagicNumber magic;
            internal ReadOnlySpan<char> parameterSet;
            internal ReadOnlySpan<byte> source;
        }
    }
}
