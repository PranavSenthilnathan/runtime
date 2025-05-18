// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class BCrypt
    {
        [LibraryImport(Libraries.BCrypt, StringMarshalling = StringMarshalling.Utf16)]
        internal static unsafe partial NTSTATUS BCryptSetProperty(
            SafeBCryptHandle hObject,
            string pszProperty,
            void* pbInput,
            int cbInput,
            int dwFlags);

        internal static unsafe void BCryptSetZeroStringProperty(SafeBCryptHandle hObject, string pszProperty, string pszValue)
        {
            fixed (void* pbInput = pszValue)
            {
                NTSTATUS status = BCryptSetProperty(
                    hObject,
                    pszProperty,
                    pbInput,
                    (pszValue.Length + 1) * 2,
                    0);

                if (status != NTSTATUS.STATUS_SUCCESS)
                {
                    throw CreateCryptographicException(status);
                }
            }
        }
    }
}
