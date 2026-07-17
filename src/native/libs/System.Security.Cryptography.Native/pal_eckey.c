// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_eckey.h"

#include <assert.h>

void CryptoNative_EcKeyDestroy(EC_KEY* r)
{
    if (API_EXISTS(EC_KEY_free))
        EC_KEY_free(r);
}

EC_KEY* CryptoNative_EcKeyCreateByOid(const char* oid)
{
    ERR_clear_error();

    if (!API_EXISTS(EC_KEY_new_by_curve_name))
        return NULL;

    // oid can be friendly name or value
    int nid = OBJ_txt2nid(oid);
    return EC_KEY_new_by_curve_name(nid);
}

int32_t CryptoNative_EcKeyGenerateKey(EC_KEY* eckey)
{
    ERR_clear_error();

    if (!API_EXISTS(EC_KEY_generate_key) || !API_EXISTS(EC_KEY_check_key))
        return 0;

    if (!EC_KEY_generate_key(eckey))
    {
        return 0;
    }

    return EC_KEY_check_key(eckey);
}

int32_t CryptoNative_EcKeyUpRef(EC_KEY* r)
{
    // No error queue impact
    if (!API_EXISTS(EC_KEY_up_ref))
        return 0;

    return EC_KEY_up_ref(r);
}

int32_t CryptoNative_EcKeyGetSize(const EC_KEY* key, int32_t* keySize)
{
    // No error queue impact

    if (!keySize)
        return 0;
    
    *keySize = 0;

    if (!key || !API_EXISTS(EC_KEY_get0_group))
        return 0;

    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (!group)
        return 0;

    *keySize = EC_GROUP_get_degree(group);

    return 1;
}

int32_t CryptoNative_EcKeyGetCurveName2(const EC_KEY* key, int32_t* nidName)
{
    // No error queue impact.

    if (!nidName)
        return 0;

    *nidName = NID_undef;

    if (!key || !API_EXISTS(EC_KEY_get0_group))
        return 0;

    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (!group)
        return 0;

    *nidName = EC_GROUP_get_curve_name(group);
    return 1;
}
