// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using Internal.NativeCrypto;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    // TODO This can just be moved inside MLDSaImplementation.Windows
    internal static class MLDsaBCryptHelpers
    {
        private static readonly SafeBCryptAlgorithmHandle s_algHandle =
            Interop.BCrypt.BCryptOpenAlgorithmProvider(BCryptNative.AlgorithmName.MLDsa);

        internal static bool IsSupported = !s_algHandle.IsInvalid;

        internal static SafeBCryptKeyHandle GenerateMLDsaKey(MLDsaAlgorithm algorithm)
        {
            string parameterSet = PqcBlobHelpers.GetParameterSet(algorithm);
            SafeBCryptKeyHandle keyHandle = Interop.BCrypt.BCryptGenerateKeyPair(s_algHandle);

            try
            {
                Interop.BCrypt.BCryptSetZeroStringProperty(keyHandle, Interop.BCrypt.BCryptPropertyStrings.BCRYPT_PARAMETER_SET_NAME, parameterSet);
                Interop.BCrypt.BCryptFinalizeKeyPair(keyHandle);
            }
            catch
            {
                // TODO Is this right? We definitely need to cleanup but BCryptFinalizeKeyPair may have failed so is it fine to still call Dispose on it?
                keyHandle?.Dispose();
                throw;
            }

            return keyHandle;
        }

        internal static SafeBCryptKeyHandle ImportPublicKeyImpl(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            return PqcBlobHelpers.EncodeMLDsaBlob(
                PqcBlobHelpers.GetParameterSet(algorithm),
                source,
                Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PUBLIC_BLOB,
                static blob => Interop.BCrypt.BCryptImportKeyPair(s_algHandle, Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PUBLIC_BLOB, blob));
        }

        internal static SafeBCryptKeyHandle ImportSecretKeyImpl(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            return PqcBlobHelpers.EncodeMLDsaBlob(
                PqcBlobHelpers.GetParameterSet(algorithm),
                source,
                Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_BLOB,
                static blob => Interop.BCrypt.BCryptImportKeyPair(s_algHandle, Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_BLOB, blob));
        }

        internal static SafeBCryptKeyHandle ImportPrivateSeedImpl(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            return PqcBlobHelpers.EncodeMLDsaBlob(
                PqcBlobHelpers.GetParameterSet(algorithm),
                source,
                Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_SEED_BLOB,
                static blob => Interop.BCrypt.BCryptImportKeyPair(s_algHandle, Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_SEED_BLOB, blob));
        }

        internal static void ExportPublicKeyImpl(SafeBCryptKeyHandle key, Span<byte> destination)
        {
            ArraySegment<byte> keyBlob = Interop.BCrypt.BCryptExportKey(key, Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PUBLIC_BLOB);

            try
            {
                ReadOnlySpan<byte> keyBytes = PqcBlobHelpers.DecodeMLDsaBlob(keyBlob, out ReadOnlySpan<char> parameterSet, out string blobType);
                Debug.Assert(blobType == Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PUBLIC_BLOB);

                // Length is known, but we'll slice just in case
                MLDsaAlgorithm algorithm = PqcBlobHelpers.GetAlgorithmFromParameterSet(parameterSet);
                Debug.Assert(keyBytes.Length == algorithm.PublicKeySizeInBytes);
                keyBytes.Slice(0, algorithm.PublicKeySizeInBytes).CopyTo(destination);
            }
            finally
            {
                CryptoPool.Return(keyBlob);
            }
        }

        internal static void ExportSecretKeyImpl(SafeBCryptKeyHandle key, Span<byte> destination)
        {
            ArraySegment<byte> keyBlob = Interop.BCrypt.BCryptExportKey(key, Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_BLOB);

            try
            {
                ReadOnlySpan<byte> keyBytes = PqcBlobHelpers.DecodeMLDsaBlob(keyBlob, out ReadOnlySpan<char> parameterSet, out string blobType);
                Debug.Assert(blobType == Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_BLOB);

                // Length is known, but we'll slice just in case
                MLDsaAlgorithm algorithm = PqcBlobHelpers.GetAlgorithmFromParameterSet(parameterSet);
                Debug.Assert(keyBytes.Length == algorithm.SecretKeySizeInBytes);
                keyBytes.Slice(0, algorithm.SecretKeySizeInBytes).CopyTo(destination);
            }
            finally
            {
                CryptoPool.Return(keyBlob);
            }
        }

        internal static void ExportPrivateSeedImpl(SafeBCryptKeyHandle key, Span<byte> destination)
        {
            ArraySegment<byte> keyBlob = Interop.BCrypt.BCryptExportKey(key, Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_SEED_BLOB);

            try
            {
                ReadOnlySpan<byte> keyBytes = PqcBlobHelpers.DecodeMLDsaBlob(keyBlob, out ReadOnlySpan<char> parameterSet, out string blobType);
                Debug.Assert(blobType == Interop.BCrypt.KeyBlobType.BCRYPT_PQDSA_PRIVATE_SEED_BLOB);

                // Length is known, but we'll slice just in case
                MLDsaAlgorithm algorithm = PqcBlobHelpers.GetAlgorithmFromParameterSet(parameterSet);
                Debug.Assert(keyBytes.Length == algorithm.PrivateSeedSizeInBytes);
                keyBytes.Slice(0, algorithm.PrivateSeedSizeInBytes).CopyTo(destination);
            }
            finally
            {
                CryptoPool.Return(keyBlob);
            }
        }
    }
}
