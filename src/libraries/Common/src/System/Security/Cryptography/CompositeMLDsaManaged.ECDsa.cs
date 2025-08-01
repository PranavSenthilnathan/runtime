// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    internal sealed partial class CompositeMLDsaManaged
    {
        private sealed class ECDsaComponent : ComponentAlgorithm
#if DESIGNTIMEINTERFACES
#pragma warning disable SA1001 // Commas should be spaced correctly
            , IComponentAlgorithmFactory<ECDsaComponent, ECDsaAlgorithm>
#pragma warning restore SA1001 // Commas should be spaced correctly
#endif
        {
            private readonly ECDsaAlgorithm _algorithm;

            private ECDsa _ecdsa;

            private ECDsaComponent(ECDsa ecdsa, ECDsaAlgorithm algorithm)
            {
                Debug.Assert(ecdsa != null);

                _ecdsa = ecdsa;
                _algorithm = algorithm;
            }

            // OpenSSL supports the brainpool curves so this can be relaxed on a per-platform basis in the future if desired.
            public static bool IsAlgorithmSupported(ECDsaAlgorithm algorithm) =>
                algorithm.CurveOid is Oids.secp256r1 or Oids.secp384r1 or Oids.secp521r1;

            public static ECDsaComponent GenerateKey(ECDsaAlgorithm algorithm)
            {
#if NET || NETSTANDARD
                return new ECDsaComponent(ECDsa.Create(algorithm.Curve), algorithm);
#else
                return new ECDsaComponent(ECDsaReflectionHelpers.CreateECDsa(algorithm.Curve), algorithm);
#endif
            }

            public static unsafe ECDsaComponent ImportPrivateKey(ECDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
            {
                try
                {
                    AsnDecoder.ReadEncodedValue(
                        source,
                        AsnEncodingRules.BER,
                        out _,
                        out _,
                        out int firstValueLength);

                    if (firstValueLength != source.Length)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    fixed (byte* ptr = &MemoryMarshal.GetReference(source))
                    {
                        using (MemoryManager<byte> manager = new PointerMemoryManager<byte>(ptr, firstValueLength))
                        {
                            ECPrivateKey ecPrivateKey = ECPrivateKey.Decode(manager.Memory, AsnEncodingRules.BER);

                            if (ecPrivateKey.Version != 1)
                            {
                                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                            }

                            // If domain parameters are present, validate that they match the composite ML-DSA algorithm.
                            if (ecPrivateKey.Parameters is ECDomainParameters domainParameters)
                            {
                                if (domainParameters.Named is not string curveOid || curveOid != algorithm.CurveOid)
                                {
                                    // The curve specified must be named and match the required curve for the composite ML-DSA algorithm.
                                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                                }
                            }

                            ECParameters parameters = new ECParameters
                            {
                                Curve = algorithm.Curve,
                            };

                            // If public key is present, add it to the parameters.
                            if (ecPrivateKey.PublicKey is ReadOnlyMemory<byte> publicKey)
                            {
                                parameters.Q = EccKeyFormatHelper.GetECPointFromUncompressedPublicKey(publicKey.Span, algorithm.KeySizeInBytes);
                            }

                            byte[] d = new byte[ecPrivateKey.PrivateKey.Length];

                            using (PinAndClear.Track(d))
                            {
                                ecPrivateKey.PrivateKey.CopyTo(d);
                                parameters.D = d;

                                parameters.Validate();

#if NET || NETSTANDARD
                                return new ECDsaComponent(ECDsa.Create(parameters), algorithm);
#else
                                return new ECDsaComponent(ECDsaReflectionHelpers.CreateECDsa(parameters), algorithm);
#endif
                            }
                        }
                    }
                }
                catch (AsnContentException e)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
                }
            }

            public static unsafe ECDsaComponent ImportPublicKey(ECDsaAlgorithm algorithm, ReadOnlySpan<byte> source)
            {
                int fieldWidth = algorithm.KeySizeInBytes;

                if (source.Length != 1 + fieldWidth * 2)
                {
                    Debug.Fail("Public key format is fixed size, so caller needs to provide exactly correct sized buffer.");
                    throw new CryptographicException();
                }

                // Implementation limitation.
                // 04 (Uncompressed ECPoint) is almost always used.
                if (source[0] != 0x04)
                {
                    throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
                }

                ECParameters parameters = new ECParameters()
                {
                    Curve = ECCurve.CreateFromValue(algorithm.CurveOid),
                    Q = new ECPoint()
                    {
                        X = source.Slice(1, fieldWidth).ToArray(),
                        Y = source.Slice(1 + fieldWidth).ToArray(),
                    }
                };

#if NET || NETSTANDARD
                return new ECDsaComponent(ECDsa.Create(parameters), algorithm);
#else
                return new ECDsaComponent(ECDsaReflectionHelpers.CreateECDsa(parameters), algorithm);
#endif
            }

            internal override bool TryExportPrivateKey(Span<byte> destination, out int bytesWritten)
            {
#if NET
                return _ecdsa.TryExportECPrivateKey(destination, out bytesWritten);
#else
                throw new PlatformNotSupportedException();
#endif
            }

            internal override bool TryExportPublicKey(Span<byte> destination, out int bytesWritten)
            {
#if NET
                int fieldWidth = _algorithm.KeySizeInBytes;

                if (destination.Length < 1 + 2 * fieldWidth)
                {
                    Debug.Fail("Public key format is fixed size, so caller needs to provide exactly correct sized buffer.");

                    bytesWritten = 0;
                    return false;
                }

                ECParameters parameters = _ecdsa.ExportParameters(includePrivateParameters: false);

                if (parameters.Q.X is not byte[] x ||
                    parameters.Q.Y is not byte[] y ||
                    x.Length != fieldWidth ||
                    y.Length != fieldWidth)
                {
                    throw new CryptographicException();
                }

                // Uncompressed ECPoint format
                destination[0] = 0x04;

                x.CopyTo(destination.Slice(1, fieldWidth));
                y.CopyTo(destination.Slice(1 + fieldWidth));

                bytesWritten = 1 + 2 * fieldWidth;
                return true;
#else
                throw new PlatformNotSupportedException();
#endif
            }

            internal override bool VerifyData(
#if NET
                ReadOnlySpan<byte> data,
#else
                byte[] data,
#endif
                ReadOnlySpan<byte> signature)
            {
#if NET
                return _ecdsa.VerifyData(data, signature, _algorithm.HashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence);
#else
                byte[] ieeeSignature;

                try
                {
                    ieeeSignature = AsymmetricAlgorithmHelpers.ConvertDerToIeee1363(signature, _algorithm.KeySizeInBits);
                }
                catch (CryptographicException)
                {
                    return false;
                }

                return _ecdsa.VerifyData(data, ieeeSignature, _algorithm.HashAlgorithmName);
#endif
            }

            internal override int SignData(
#if NET
                ReadOnlySpan<byte> data,
#else
                byte[] data,
#endif
                Span<byte> destination)
            {
#if NET
                if (!_ecdsa.TrySignData(data, destination, _algorithm.HashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence, out int bytesWritten))
                {
                    Debug.Fail("Buffer size should have been validated by caller.");
                    throw new CryptographicException();
                }

                return bytesWritten;
#else
                byte[] ieeeSignature = _ecdsa.SignData(data, _algorithm.HashAlgorithmName);

                if (!AsymmetricAlgorithmHelpers.TryConvertIeee1363ToDer(ieeeSignature, destination, out int bytesWritten))
                {
                    Debug.Fail("Buffer size should have been validated by caller.");
                    throw new CryptographicException();
                }

                return bytesWritten;
#endif
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _ecdsa?.Dispose();
                    _ecdsa = null!;
                }

                base.Dispose(disposing);
            }
        }
    }
}
