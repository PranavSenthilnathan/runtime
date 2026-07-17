// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_evp_pkey_eckey.h"
#include "pal_ecc_import_export.h"

#include <assert.h>

EVP_PKEY* CryptoNative_CreateEvpPkeyFromEcKey(EC_KEY* ecKey, int32_t* outKeySize)
{
    assert(ecKey != NULL);
    assert(outKeySize != NULL);

    ERR_clear_error();

    *outKeySize = 0;

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey)
        return NULL;

    // EVP_PKEY_set1_EC_KEY up-refs the EC_KEY internally. It is deprecated in OpenSSL 3.0
    // and removed in 4.0; when it is unavailable, return an invalid handle so the managed
    // ECDsaOpenSsl(IntPtr)/ECDiffieHellmanOpenSsl(IntPtr) ctors surface the failure as an
    // exception instead of dereferencing a NULL function pointer.
    if (!API_EXISTS(EVP_PKEY_set1_EC_KEY) || !EVP_PKEY_set1_EC_KEY(pkey, ecKey))
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    int32_t keySize = CryptoNative_EvpPKeyGetEcKeySize(pkey);
    if (keySize == 0)
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    *outKeySize = keySize;
    return pkey;
}
