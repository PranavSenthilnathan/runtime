// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_evp_pkey.h"
#include "pal_evp_pkey_rsa.h"
#include "pal_utilities.h"
#include "openssl.h"
#include <assert.h>

static int HasNoPrivateKey(const RSA* rsa);

EVP_PKEY* CryptoNative_EvpPKeyCreateRsa(RSA* currentKey)
{
    assert(currentKey != NULL);

    ERR_clear_error();

    EVP_PKEY* pkey = EVP_PKEY_new();

    if (pkey == NULL)
    {
        return NULL;
    }

    if (!EVP_PKEY_set1_RSA(pkey, currentKey))
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}

EVP_PKEY* CryptoNative_RsaGenerateKey(int keySize)
{
    ERR_clear_error();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (ctx == NULL)
    {
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    EVP_PKEY* ret = NULL;

    if (EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) == 1 &&
        EVP_PKEY_keygen(ctx, &pkey) == 1)
    {
        ret = pkey;
        pkey = NULL;
    }

    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static bool ConfigureEncryption(EVP_PKEY_CTX* ctx, RsaPaddingMode padding, const EVP_MD* digest)
{
    if (padding == RsaPaddingPkcs1)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        {
            return false;
        }

        // OpenSSL 3.2 introduced a change where PKCS#1 RSA decryption does not fail for invalid padding.
        // If the padding is invalid, the decryption operation returns random data.
        // See https://github.com/openssl/openssl/pull/13817 for background.
        // Some Linux distributions backported this change to previous versions of OpenSSL.
        // Here we do a best-effort to set a flag to revert the behavior to failing if the padding is invalid.
        ERR_set_mark();

        EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pkcs1_implicit_rejection", "0");

        // Undo any changes to the error queue that may have occured while configuring implicit rejection if the
        // current version does not support implicit rejection.
        ERR_pop_to_mark();
    }
    else
    {
        assert(padding == RsaPaddingOaepOrPss);

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        {
            return false;
        }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, digest) <= 0)
#pragma clang diagnostic pop
        {
            return false;
        }
    }

    return true;
}

int32_t CryptoNative_RsaDecrypt(EVP_PKEY* pkey,
                                void* extraHandle,
                                const uint8_t* source,
                                int32_t sourceLen,
                                RsaPaddingMode padding,
                                const EVP_MD* digest,
                                uint8_t* destination,
                                int32_t destinationLen)
{
    assert(pkey != NULL);
    assert(source != NULL);
    assert(destination != NULL);
    assert(padding >= RsaPaddingPkcs1 && padding <= RsaPaddingOaepOrPss);
    assert(digest != NULL || padding == RsaPaddingPkcs1);

    ERR_clear_error();

    EVP_PKEY_CTX* ctx = EvpPKeyCtxCreateFromPKey(pkey, extraHandle);

    int ret = -1;

    if (ctx == NULL || EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        goto done;
    }

    if (!ConfigureEncryption(ctx, padding, digest))
    {
        goto done;
    }

    // This check will not work with hardware keys coming from OpenSSL providers
    // because providers don't seem to set RSA_FLAG_EXT_PKEY (the tpm2 most notably)
    // ENGINE-s may or may not set it.
    // This is needed only on OpenSSL < 3.0,
    // see: https://github.com/dotnet/runtime/issues/53345
    if (CryptoNative_OpenSslVersionNumber() < OPENSSL_VERSION_3_0_RTM)
    {
        const RSA* rsa = EVP_PKEY_get0_RSA(pkey);

        if (rsa == NULL || HasNoPrivateKey(rsa))
        {
            ERR_PUT_error(ERR_LIB_RSA, RSA_F_RSA_NULL_PRIVATE_DECRYPT, RSA_R_VALUE_MISSING, __FILE__, __LINE__);
            goto done;
        }
    }

    size_t written = Int32ToSizeT(destinationLen);

    if (EVP_PKEY_decrypt(ctx, destination, &written, source, Int32ToSizeT(sourceLen)) > 0)
    {
        ret = SizeTToInt32(written);
    }

done:
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}

int32_t CryptoNative_RsaEncrypt(EVP_PKEY* pkey,
                                void* extraHandle,
                                const uint8_t* source,
                                int32_t sourceLen,
                                RsaPaddingMode padding,
                                const EVP_MD* digest,
                                uint8_t* destination,
                                int32_t destinationLen)
{
    assert(pkey != NULL);
    assert(destination != NULL);
    assert(padding >= RsaPaddingPkcs1 && padding <= RsaPaddingOaepOrPss);
    assert(digest != NULL || padding == RsaPaddingPkcs1);

    ERR_clear_error();

    EVP_PKEY_CTX* ctx = EvpPKeyCtxCreateFromPKey(pkey, extraHandle);

    int ret = -1;

    if (ctx == NULL || EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        goto done;
    }

    if (!ConfigureEncryption(ctx, padding, digest))
    {
        goto done;
    }

    size_t written = Int32ToSizeT(destinationLen);

    if (EVP_PKEY_encrypt(ctx, destination, &written, source, Int32ToSizeT(sourceLen)) > 0)
    {
        ret = SizeTToInt32(written);
    }

done:
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}

static bool ConfigureSignature(EVP_PKEY_CTX* ctx, RsaPaddingMode padding, const EVP_MD* digest)
{

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
    if (EVP_PKEY_CTX_set_signature_md(ctx, digest) <= 0)
#pragma clang diagnostic pop
    {
        return false;
    }

    if (padding == RsaPaddingPkcs1)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        {
            return false;
        }
    }
    else
    {
        assert(padding == RsaPaddingOaepOrPss);

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
        {
            return false;
        }
    }

    return true;
}

int32_t CryptoNative_RsaSignHash(EVP_PKEY* pkey,
                                 void* extraHandle,
                                 RsaPaddingMode padding,
                                 const EVP_MD* digest,
                                 const uint8_t* hash,
                                 int32_t hashLen,
                                 uint8_t* destination,
                                 int32_t destinationLen)
{
    assert(pkey != NULL);
    assert(destination != NULL);
    assert(padding >= RsaPaddingPkcs1 && padding <= RsaPaddingOaepOrPss);
    assert(digest != NULL || padding == RsaPaddingPkcs1);

    ERR_clear_error();

    EVP_PKEY_CTX* ctx = EvpPKeyCtxCreateFromPKey(pkey, extraHandle);

    int ret = -1;

    if (ctx == NULL || EVP_PKEY_sign_init(ctx) <= 0)
    {
        goto done;
    }

    if (!ConfigureSignature(ctx, padding, digest))
    {
        goto done;
    }

    // This check will not work with hardware keys coming from OpenSSL providers
    // because providers don't seem to set RSA_FLAG_EXT_PKEY (the tpm2 most notably)
    // ENGINE-s may or may not set it.
    // This is needed only on OpenSSL < 3.0,
    // see: https://github.com/dotnet/runtime/issues/53345
    if (CryptoNative_OpenSslVersionNumber() < OPENSSL_VERSION_3_0_RTM)
    {
        const RSA* rsa = EVP_PKEY_get0_RSA(pkey);

        if (rsa == NULL || HasNoPrivateKey(rsa))
        {
            ERR_PUT_error(ERR_LIB_RSA, RSA_F_RSA_NULL_PRIVATE_DECRYPT, RSA_R_VALUE_MISSING, __FILE__, __LINE__);
            goto done;
        }
    }

    size_t written = Int32ToSizeT(destinationLen);

    if (EVP_PKEY_sign(ctx, destination, &written, hash, Int32ToSizeT(hashLen)) > 0)
    {
        ret = SizeTToInt32(written);
    }

done:
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}

int32_t CryptoNative_RsaVerifyHash(EVP_PKEY* pkey,
                                   void* extraHandle,
                                   RsaPaddingMode padding,
                                   const EVP_MD* digest,
                                   const uint8_t* hash,
                                   int32_t hashLen,
                                   const uint8_t* signature,
                                   int32_t signatureLen)
{
    assert(pkey != NULL);
    assert(signature != NULL);
    assert(padding >= RsaPaddingPkcs1 && padding <= RsaPaddingOaepOrPss);
    assert(digest != NULL || padding == RsaPaddingPkcs1);

    ERR_clear_error();

    EVP_PKEY_CTX* ctx = EvpPKeyCtxCreateFromPKey(pkey, extraHandle);

    int ret = -1;

    if (ctx == NULL || EVP_PKEY_verify_init(ctx) <= 0)
    {
        goto done;
    }

    if (!ConfigureSignature(ctx, padding, digest))
    {
        goto done;
    }

    // EVP_PKEY_verify is not consistent on whether a missized hash is an error or just a mismatch.
    // Normalize to mismatch.
    if (hashLen != EVP_MD_get_size(digest))
    {
        ret = 0;
        goto done;
    }

    ret = EVP_PKEY_verify(ctx, signature, Int32ToSizeT(signatureLen), hash, Int32ToSizeT(hashLen));

done:
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}

static int HasNoPrivateKey(const RSA* rsa)
{
    if (rsa == NULL)
        return 1;

    // Shared pointer, don't free.
    const RSA_METHOD* meth = RSA_get_method(rsa);

    // The method has described itself as having the private key external to the structure.
    // That doesn't mean it's actually present, but we can't tell.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
    if (RSA_test_flags(rsa, RSA_FLAG_EXT_PKEY) || RSA_meth_get_flags((RSA_METHOD*)meth) & RSA_FLAG_EXT_PKEY)
#pragma clang diagnostic pop
    {
        return 0;
    }

    // In the event that there's a middle-ground where we report failure when success is expected,
    // one could do something like check if the RSA_METHOD intercepts all private key operations:
    //
    // * meth->rsa_priv_enc
    // * meth->rsa_priv_dec
    // * meth->rsa_sign (in 1.0.x this is only respected if the RSA_FLAG_SIGN_VER flag is asserted)
    //
    // But, for now, leave it at the EXT_PKEY flag test.

    // The module is documented as accepting either d or the full set of CRT parameters (p, q, dp, dq, qInv)
    // So if we see d, we're good. Otherwise, if any of the rest are missing, we're public-only.
    const BIGNUM* d;
    RSA_get0_key(rsa, NULL, NULL, &d);

    if (d != NULL)
    {
        return 0;
    }

    const BIGNUM* p;
    const BIGNUM* q;
    const BIGNUM* dmp1;
    const BIGNUM* dmq1;
    const BIGNUM* iqmp;

    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

    if (p == NULL || q == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL)
    {
        return 1;
    }

    return 0;
}
