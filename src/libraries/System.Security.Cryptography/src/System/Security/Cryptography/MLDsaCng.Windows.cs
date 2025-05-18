// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

using BCRYPT_PQDSA_PADDING_INFO = Interop.BCrypt.BCRYPT_PQDSA_PADDING_INFO;

namespace System.Security.Cryptography
{
    public sealed partial class MLDsaCng : MLDsa
    {
        private const string NCRYPT_MLDSA_PARAMETER_SET_44 = PqcBlobHelpers.BCRYPT_MLDSA_PARAMETER_SET_44;
        private const string NCRYPT_MLDSA_PARAMETER_SET_65 = PqcBlobHelpers.BCRYPT_MLDSA_PARAMETER_SET_65;
        private const string NCRYPT_MLDSA_PARAMETER_SET_87 = PqcBlobHelpers.BCRYPT_MLDSA_PARAMETER_SET_87;

        /// <summary>
        ///     Creates a new MLDsaCng object that will use the specified key. Unlike the public
        ///     constructor, this does not copy the key and ownership is transferred. The
        ///     <paramref name="transferOwnership"/> parameter must be true.
        /// </summary>
        /// <param name="key">Key to use for MLDsa operations</param>
        /// <param name="transferOwnership">
        /// Must be true. Signals that ownership of <paramref name="key"/> will be transferred to the new instance.
        /// </param>
        internal MLDsaCng(CngKey key, bool transferOwnership)
            : base(AlgorithmFromHandleNoDuplicate(key))
        {
            Debug.Assert(key is not null);
            Debug.Assert(key.AlgorithmGroup == CngAlgorithmGroup.MLDsa);
            Debug.Assert(transferOwnership);

            _key = key;
        }

        private static partial MLDsaAlgorithm AlgorithmFromHandle(CngKey key, out CngKey duplicateKey)
        {
            ArgumentNullException.ThrowIfNull(key);

            if (key.AlgorithmGroup != CngAlgorithmGroup.MLDsa)
            {
                // TODO resx
                throw new ArgumentException();
            }

            MLDsaAlgorithm algorithm = AlgorithmFromHandleImpl(key);
            duplicateKey = CngAlgorithmCore.Duplicate(key);
            return algorithm;
        }

        private static MLDsaAlgorithm AlgorithmFromHandleNoDuplicate(CngKey key)
        {
            if (key.AlgorithmGroup != CngAlgorithmGroup.MLDsa)
            {
                // TODO resx
                throw new CryptographicException();
            }

            Debug.Assert(key is not null);


            return AlgorithmFromHandleImpl(key);
        }

        private static MLDsaAlgorithm AlgorithmFromHandleImpl(CngKey key)
        {
            string? parameterSet =
                key.Handle.GetPropertyAsString(KeyPropertyName.ParameterSetName, CngPropertyOptions.None);

            return parameterSet switch
            {
                NCRYPT_MLDSA_PARAMETER_SET_44 => MLDsaAlgorithm.MLDsa44,
                NCRYPT_MLDSA_PARAMETER_SET_65 => MLDsaAlgorithm.MLDsa65,
                NCRYPT_MLDSA_PARAMETER_SET_87 => MLDsaAlgorithm.MLDsa87,
                // TODO resx
                _ => throw new CryptographicException(),
            };
        }

        public partial CngKey GetCngKey()
        {
            ThrowIfDisposed();

            // TODO Should this duplicate the key? Other algos don't seem to in their
            // Key property, but making this a method might imply to users that this
            // a new copy that we made for them
            return _key;
        }

        protected override void ExportMLDsaPublicKeyCore(Span<byte> destination)
        {
            // TODO can avoid an allocation here with overload to Export since we know the bcrypt blob size.
            // We just need to handle the case that ncrypt adds stuff to it and makes it bigger.
            byte[] blob = _key.Export(CngKeyBlobFormat.PQDsaPublicBlob);
            ReadOnlySpan<byte> keyBytes = PqcBlobHelpers.DecodeMLDsaBlob(blob, out ReadOnlySpan<char> parameterSet, out string blobType);

            if (PqcBlobHelpers.GetAlgorithmFromParameterSet(parameterSet) != Algorithm)
            {
                // TODO resx
                throw new CryptographicException();
            }

            if (blobType != CngKeyBlobFormat.PQDsaPublicBlob.Format)
            {
                // TODO resx
                throw new CryptographicException();
            }

            if (keyBytes.Length != Algorithm.PublicKeySizeInBytes)
            {
                // TODO resx
                throw new CryptographicException();
            }

            keyBytes.CopyTo(destination);
        }

        protected override void ExportMLDsaPrivateSeedCore(Span<byte> destination)
        {
            bool encryptedOnlyExport = CngPkcs8.AllowsOnlyEncryptedExport(_key);

            if (encryptedOnlyExport)
            {
                const string TemporaryExportPassword = "DotnetExportPhrase";
                byte[] exported = _key.ExportPkcs8KeyBlob(TemporaryExportPassword, 1);

                // TODO This is a hack.. change it to use the internal parser directly
                using (MLDsa cloned = MLDsa.ImportEncryptedPkcs8PrivateKey(TemporaryExportPassword, exported))
                {
                    cloned.ExportMLDsaPrivateSeed(destination);
                    return;
                }
            }

            byte[] blob = _key.Export(CngKeyBlobFormat.PQDsaPrivateSeedBlob);
            ReadOnlySpan<byte> keyBytes = PqcBlobHelpers.DecodeMLDsaBlob(blob, out ReadOnlySpan<char> parameterSet, out string blobType);

            if (PqcBlobHelpers.GetAlgorithmFromParameterSet(parameterSet) != Algorithm)
            {
                // TODO resx
                throw new CryptographicException();
            }

            if (blobType != CngKeyBlobFormat.PQDsaPrivateSeedBlob.Format)
            {
                // TODO resx
                throw new CryptographicException();
            }

            if (keyBytes.Length != Algorithm.PrivateSeedSizeInBytes)
            {
                // TODO resx
                throw new CryptographicException();
            }

            keyBytes.CopyTo(destination);
        }

        protected override void ExportMLDsaSecretKeyCore(Span<byte> destination)
        {
            bool encryptedOnlyExport = CngPkcs8.AllowsOnlyEncryptedExport(_key);

            if (encryptedOnlyExport)
            {
                const string TemporaryExportPassword = "DotnetExportPhrase";
                byte[] exported = _key.ExportPkcs8KeyBlob(TemporaryExportPassword, 1);

                // TODO This is a hack.. change it to use the internal parser directly
                // TODO we might still need MLDsa IF we find that the PKCS#8 only contains seed
                using (MLDsa cloned = MLDsa.ImportEncryptedPkcs8PrivateKey(TemporaryExportPassword, exported))
                {
                    cloned.ExportMLDsaSecretKey(destination);
                    return;
                }
            }

            byte[] blob = _key.Export(CngKeyBlobFormat.PQDsaPrivateBlob);
            ReadOnlySpan<byte> keyBytes = PqcBlobHelpers.DecodeMLDsaBlob(blob, out ReadOnlySpan<char> parameterSet, out string blobType);

            if (PqcBlobHelpers.GetAlgorithmFromParameterSet(parameterSet) != Algorithm)
            {
                // TODO resx
                throw new CryptographicException();
            }

            if (blobType != CngKeyBlobFormat.PQDsaPrivateBlob.Format)
            {
                // TODO resx
                throw new CryptographicException();
            }

            if (keyBytes.Length != Algorithm.SecretKeySizeInBytes)
            {
                // TODO resx
                throw new CryptographicException();
            }

            keyBytes.CopyTo(destination);
        }

        protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
        {
            bool encryptedOnlyExport = CngPkcs8.AllowsOnlyEncryptedExport(_key);

            if (encryptedOnlyExport)
            {
                const string TemporaryExportPassword = "DotnetExportPhrase";
                byte[] exported = _key.ExportPkcs8KeyBlob(TemporaryExportPassword, 1);

                // TODO This is a hack.. change it to use the internal parser directly
                using (MLDsa cloned = MLDsa.ImportEncryptedPkcs8PrivateKey(TemporaryExportPassword, exported))
                {
                    return cloned.TryExportPkcs8PrivateKey(destination, out bytesWritten);
                }
            }

            return _key.TryExportKeyBlob(
                Interop.NCrypt.NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                destination,
                out bytesWritten);
        }

        protected override unsafe void SignDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, Span<byte> destination)
        {
            if (data.Length == 0)
            {
                data = Array.Empty<byte>();
            }

            using (SafeNCryptKeyHandle duplicatedHandle = _key.Handle)
            {
                if (context.Length == 0)
                {
                    duplicatedHandle.SignHash(
                        data,
                        destination,
                        Interop.NCrypt.AsymmetricPaddingMode.None,
                        pPaddingInfo: null);
                }
                else
                {
                    fixed (void* pContext = context)
                    {
                        BCRYPT_PQDSA_PADDING_INFO paddingInfo = default;
                        paddingInfo.pbCtx = (IntPtr)pContext;
                        paddingInfo.cbCtx = context.Length;

                        duplicatedHandle.SignHash(
                            data,
                            destination,
                            Interop.NCrypt.AsymmetricPaddingMode.NCRYPT_PAD_PQDSA_FLAG,
                            &paddingInfo);
                    }
                }
            }
        }

        protected override unsafe bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature)
        {
            if (data.Length == 0)
            {
                data = Array.Empty<byte>();
            }

            using (SafeNCryptKeyHandle duplicatedHandle = _key.Handle)
            {
                if (context.Length == 0)
                {
                    return duplicatedHandle.VerifyHash(
                        data,
                        signature,
                        Interop.NCrypt.AsymmetricPaddingMode.None,
                        pPaddingInfo: null);
                }
                else
                {
                    fixed (void* pContext = context)
                    {
                        BCRYPT_PQDSA_PADDING_INFO paddingInfo = default;
                        paddingInfo.pbCtx = (IntPtr)pContext;
                        paddingInfo.cbCtx = context.Length;

                        return duplicatedHandle.VerifyHash(
                            data,
                            signature,
                            Interop.NCrypt.AsymmetricPaddingMode.NCRYPT_PAD_PQDSA_FLAG,
                            &paddingInfo);
                    }
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            _key.Dispose();
            _key = null!;
        }
    }
}
