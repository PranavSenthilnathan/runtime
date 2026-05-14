// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    internal static partial class ECOpenSsl
    {
        internal static SafeEvpPKeyHandle GenerateECKey(int keySize)
        {
            string oid = keySize switch
            {
                256 => ECOpenSsl.ECDSA_P256_OID_VALUE,
                384 => ECOpenSsl.ECDSA_P384_OID_VALUE,
                521 => ECOpenSsl.ECDSA_P521_OID_VALUE,
                _ => throw new InvalidOperationException(SR.Cryptography_InvalidKeySize),
            };

            SafeEvpPKeyHandle? pkey = Interop.Crypto.EvpPKeyGenerateByEcCurveOid(oid, out _);

            if (pkey is not null)
            {
                return pkey;
            }

            // Fallback to legacy EC_KEY path
            SafeEvpPKeyHandle ret = ImportECKeyCore(new ECOpenSsl(keySize), out int createdKeySize);
            Debug.Assert(keySize == createdKeySize);
            return ret;
        }

        internal static SafeEvpPKeyHandle GenerateECKey(ECCurve curve, out int keySize)
        {
            curve.Validate();

            if (curve.IsNamed)
            {
                string oid = !string.IsNullOrEmpty(curve.Oid.Value) ? curve.Oid.Value : curve.Oid.FriendlyName!;

                SafeEvpPKeyHandle? pkey = Interop.Crypto.EvpPKeyGenerateByEcCurveOid(oid, out keySize);

                if (pkey is not null && keySize != 0)
                {
                    return pkey;
                }

                pkey?.Dispose();
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }
            else if (curve.IsPrime || curve.IsCharacteristic2)
            {
                byte[] pField = curve.IsPrime ? curve.Prime! : curve.Polynomial!;

                // Pass null Q and null D to trigger key generation instead of import.
                SafeEvpPKeyHandle? pkey = Interop.Crypto.EvpPKeyCreateByEcExplicitParameters(
                    curve.CurveType,
                    null,
                    null,
                    null,
                    pField,
                    curve.A,
                    curve.B,
                    curve.G.X,
                    curve.G.Y,
                    curve.Order,
                    curve.Cofactor,
                    curve.Seed);

                if (pkey is not null)
                {
                    keySize = Interop.Crypto.EvpPKeyGetEcFieldDegree(pkey);

                    if (keySize != 0)
                    {
                        return pkey;
                    }

                    pkey.Dispose();
                }
            }

            // Fallback to legacy EC_KEY path (explicit curves or OpenSSL < 3.0)
            return ImportECKeyCore(new ECOpenSsl(curve), out keySize);
        }

        internal static SafeEvpPKeyHandle ImportECKey(ECParameters parameters, out int keySize)
        {
            parameters.Validate();

            if (parameters.Curve.IsNamed)
            {
                string oid = !string.IsNullOrEmpty(parameters.Curve.Oid.Value) ?
                    parameters.Curve.Oid.Value : parameters.Curve.Oid.FriendlyName!;

                SafeEvpPKeyHandle? pkey = Interop.Crypto.EvpPKeyCreateByEcParameters(
                    oid,
                    parameters.Q.X,
                    parameters.Q.Y,
                    parameters.D);

                if (pkey is not null)
                {
                    keySize = Interop.Crypto.EvpPKeyGetEcFieldDegree(pkey);

                    if (keySize != 0)
                    {
                        return pkey;
                    }

                    pkey.Dispose();
                }
            }
            else if (parameters.Curve.IsPrime || parameters.Curve.IsCharacteristic2)
            {
                byte[] pField = parameters.Curve.IsPrime ? parameters.Curve.Prime! : parameters.Curve.Polynomial!;

                SafeEvpPKeyHandle? pkey = Interop.Crypto.EvpPKeyCreateByEcExplicitParameters(
                    parameters.Curve.CurveType,
                    parameters.Q.X,
                    parameters.Q.Y,
                    parameters.D,
                    pField,
                    parameters.Curve.A,
                    parameters.Curve.B,
                    parameters.Curve.G.X,
                    parameters.Curve.G.Y,
                    parameters.Curve.Order,
                    parameters.Curve.Cofactor,
                    parameters.Curve.Seed);

                if (pkey is not null)
                {
                    keySize = Interop.Crypto.EvpPKeyGetEcFieldDegree(pkey);

                    if (keySize != 0)
                    {
                        return pkey;
                    }

                    pkey.Dispose();
                }
            }

            // Fallback to legacy EC_KEY path
            return ImportECKeyCore(new ECOpenSsl(parameters), out keySize);
        }

        // Note: This method takes ownership of ecOpenSsl and disposes it
        private static SafeEvpPKeyHandle ImportECKeyCore(ECOpenSsl ecOpenSsl, out int keySize)
        {
            using (ECOpenSsl ec = ecOpenSsl)
            {
                SafeEvpPKeyHandle handle = Interop.Crypto.CreateEvpPkeyFromEcKey(ec.Value);
                keySize = ec.KeySize;
                return handle;
            }
        }
    }
}
