// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class BCrypt
    {
        [Flags]
        private enum BCryptSignVerifyFlags : uint
        {
            BCRYPT_PAD_PKCS1 = 2,
            BCRYPT_PAD_PSS = 8,
            BCRYPT_PAD_PQDSA = 32,
        }

        [LibraryImport(Libraries.BCrypt)]
        private static unsafe partial NTSTATUS BCryptVerifySignature(
            SafeBCryptKeyHandle hKey,
            void* pPaddingInfo,
            byte* pbHash,
            int cbHash,
            byte* pbSignature,
            int cbSignature,
            BCryptSignVerifyFlags dwFlags);

        internal static unsafe bool BCryptVerifySignaturePkcs1(
            SafeBCryptKeyHandle key,
            ReadOnlySpan<byte> hash,
            ReadOnlySpan<byte> signature,
            string hashAlgorithmName)
        {
            NTSTATUS status;

            fixed (char* pHashAlgorithmName = hashAlgorithmName)
            fixed (byte* pHash = &MemoryMarshal.GetReference(hash))
            fixed (byte* pSignature = &MemoryMarshal.GetReference(signature))
            {
                BCRYPT_PKCS1_PADDING_INFO paddingInfo = default;
                paddingInfo.pszAlgId = (IntPtr)pHashAlgorithmName;

                status = BCryptVerifySignature(
                    key,
                    &paddingInfo,
                    pHash,
                    hash.Length,
                    pSignature,
                    signature.Length,
                    BCryptSignVerifyFlags.BCRYPT_PAD_PKCS1);
            }

            return status == NTSTATUS.STATUS_SUCCESS;
        }

        internal static unsafe bool BCryptVerifySignaturePss(
            SafeBCryptKeyHandle key,
            ReadOnlySpan<byte> hash,
            ReadOnlySpan<byte> signature,
            string hashAlgorithmName)
        {

            NTSTATUS status;

            fixed (char* pHashAlgorithmName = hashAlgorithmName)
            fixed (byte* pHash = &MemoryMarshal.GetReference(hash))
            fixed (byte* pSignature = &MemoryMarshal.GetReference(signature))
            {
                BCRYPT_PSS_PADDING_INFO paddingInfo = default;
                paddingInfo.pszAlgId = (IntPtr)pHashAlgorithmName;
                paddingInfo.cbSalt = hash.Length;

                status = BCryptVerifySignature(
                    key,
                    &paddingInfo,
                    pHash,
                    hash.Length,
                    pSignature,
                    signature.Length,
                    BCryptSignVerifyFlags.BCRYPT_PAD_PSS);
            }

            return status == NTSTATUS.STATUS_SUCCESS;
        }

        internal static unsafe bool BCryptVerifySignaturePure(
            SafeBCryptKeyHandle key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature)
        {
            NTSTATUS status;

            // TODO for some reason window complains when verifying null data
            // (span created from ReadOnlySpan<byte>.Empty).. is this a bug in their code?
            if (data.Length == 0)
            {
                data = Array.Empty<byte>();
            }

            fixed (byte* pData = &MemoryMarshal.GetReference(data))
            fixed (byte* pSignature = &MemoryMarshal.GetReference(signature))
            {
                if (context.Length == 0)
                {
                    status = BCryptVerifySignature(
                        key,
                        pPaddingInfo: null,
                        pData,
                        data.Length,
                        pSignature,
                        signature.Length,
                        default(BCryptSignVerifyFlags));
                }
                else
                {
                    fixed (byte* pContext = &MemoryMarshal.GetReference(context))
                    {
                        BCRYPT_PQDSA_PADDING_INFO paddingInfo = default;
                        paddingInfo.pbCtx = (IntPtr)pContext;
                        paddingInfo.cbCtx = context.Length;

                        status = BCryptVerifySignature(
                            key,
                            &paddingInfo,
                            pData,
                            data.Length,
                            pSignature,
                            signature.Length,
                            BCryptSignVerifyFlags.BCRYPT_PAD_PQDSA);
                    }
                }
            }

            if (status == NTSTATUS.STATUS_INVALID_PARAMETER)
            {
                Debug.Fail("Inputs were not validated.");
            }

            return status == NTSTATUS.STATUS_SUCCESS;
        }
    }
}
