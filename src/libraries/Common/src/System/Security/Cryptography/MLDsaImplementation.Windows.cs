// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.NativeCrypto;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    internal sealed partial class MLDsaImplementation : MLDsa
    {
        private SafeBCryptKeyHandle _key;

        private MLDsaImplementation(MLDsaAlgorithm algorithm, SafeBCryptKeyHandle key)
            : base(algorithm)
        {
            _key = key;
        }

        internal static partial bool SupportsAny() => MLDsaBCryptHelpers.IsSupported;

        protected override void SignDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, Span<byte> destination) =>
            Interop.BCrypt.BCryptSignHashPure(_key, data, context, destination);

        protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
            Interop.BCrypt.BCryptVerifySignaturePure(_key, data, context, signature);

        protected override void ExportMLDsaPublicKeyCore(Span<byte> destination) =>
            MLDsaBCryptHelpers.ExportPublicKeyImpl(_key, destination);

        protected override void ExportMLDsaSecretKeyCore(Span<byte> destination) =>
            MLDsaBCryptHelpers.ExportSecretKeyImpl(_key, destination);

        protected override void ExportMLDsaPrivateSeedCore(Span<byte> destination) =>
            MLDsaBCryptHelpers.ExportPrivateSeedImpl(_key, destination);

        protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten) =>
            throw new PlatformNotSupportedException();

        internal static partial MLDsaImplementation GenerateKeyImpl(MLDsaAlgorithm algorithm) =>
            new MLDsaImplementation(algorithm, MLDsaBCryptHelpers.GenerateMLDsaKey(algorithm));

        internal static partial MLDsaImplementation ImportPublicKey(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            SafeBCryptKeyHandle key = MLDsaBCryptHelpers.ImportPublicKeyImpl(algorithm, source);
            return new MLDsaImplementation(algorithm, key);
        }

        internal static partial MLDsaImplementation ImportPkcs8PrivateKeyValue(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> source) =>
            throw new PlatformNotSupportedException();

        internal static partial MLDsaImplementation ImportSecretKey(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            SafeBCryptKeyHandle key = MLDsaBCryptHelpers.ImportSecretKeyImpl(algorithm, source);
            return new MLDsaImplementation(algorithm, key);
        }

        internal static partial MLDsaImplementation ImportSeed(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            SafeBCryptKeyHandle key = MLDsaBCryptHelpers.ImportPrivateSeedImpl(algorithm, source);
            return new MLDsaImplementation(algorithm, key);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _key?.Dispose();
                _key = null!;
            }
        }
    }
}
