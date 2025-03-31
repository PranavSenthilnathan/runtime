// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "opensslshim.h"
#include "pal_compiler.h"
#include "pal_types.h"

typedef enum
{
    PalSlhDsaTypeId_Unknown   = 0,
    PalSlhDsaTypeId_Sha2_128s = 1,
    PalSlhDsaTypeId_Shake128s = 2,
    PalSlhDsaTypeId_Sha2_128f = 3,
    PalSlhDsaTypeId_Shake128f = 4,
    PalSlhDsaTypeId_Sha2_192s = 5,
    PalSlhDsaTypeId_Shake192s = 6,
    PalSlhDsaTypeId_Sha2_192f = 7,
    PalSlhDsaTypeId_Shake192f = 8,
    PalSlhDsaTypeId_Sha2_256s = 9,
    PalSlhDsaTypeId_Shake256s = 10,
    PalSlhDsaTypeId_Sha2_256f = 11,
    PalSlhDsaTypeId_Shake256f = 12,
} PalSlhDsaTypeId;

/*
Generates a new EVP_PKEY with random parameters or if seed is not NULL, uses the seed to generate the key.
The keyType is the type of the key (e.g., "SLH-DSA-SHA2-128s").
*/
PALEXPORT EVP_PKEY* CryptoNative_SlhDsaGenerateKey(const char* keyType, uint8_t* seed, int32_t seedLen);

/*
Sign a message using the provided SLH-DSA key.

Returns 1 on success, 0 on a mismatched signature, -1 on error.
*/
PALEXPORT int32_t CryptoNative_SlhDsaSignPure(EVP_PKEY *pkey,
                                              void* extraHandle,
                                              uint8_t* msg, int32_t msgLen,
                                              uint8_t* context, int32_t contextLen,
                                              uint8_t* destination, int32_t destinationLen);

/*
Verify a message using the provided SLH-DSA key.

Returns 1 on a verified signature, 0 on a mismatched signature, -1 on error.
*/
PALEXPORT int32_t CryptoNative_SlhDsaVerifyPure(EVP_PKEY *pkey,
                                                void* extraHandle,
                                                uint8_t* msg, int32_t msgLen,
                                                uint8_t* context, int32_t contextLen,
                                                uint8_t* sig, int32_t sigLen);

/*
Export the secret key from the given SLH-DSA key.
*/
PALEXPORT int32_t CryptoNative_SlhDsaExportSecretKey(const EVP_PKEY* pKey, uint8_t* destination, int32_t destinationLength);

/*
Export the seed from the given SLH-DSA key which can be used to generate secret key.
*/
PALEXPORT int32_t CryptoNative_SlhDsaExportSeed(const EVP_PKEY* pKey, uint8_t* destination, int32_t destinationLength);

/*
Export the public key from the given SLH-DSA key.
*/
PALEXPORT int32_t CryptoNative_SlhDsaExportPublicKey(const EVP_PKEY* pKey, uint8_t* destination, int32_t destinationLength);

/*
Get the SLH-DSA type ID for the given SLH-DSA key.
*/
PALEXPORT int32_t CryptoNative_SlhDsaGetPalId(const EVP_PKEY* pKey, int32_t* slhDsaTypeId);
