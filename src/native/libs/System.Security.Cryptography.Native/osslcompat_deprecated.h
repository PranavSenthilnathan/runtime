// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Prototypes for OpenSSL functions that were deprecated in OpenSSL 3.0. They are re-declared
// here for builds where the public headers no longer expose them -- either because a future
// OpenSSL removed the declarations, or because this is the opt-in
// CRYPTO_VALIDATE_NO_DEPRECATED_OSSL validation build (OPENSSL_API_COMPAT >= 3.0 +
// OPENSSL_NO_DEPRECATED). The symbols still exist in libcrypto for OpenSSL 3.x, so
// re-declaring them here lets the shim continue to bind and call them where a deprecated
// fallback is still required.
//
// Unless noted otherwise, every call site of a function declared here must be guarded
// with API_EXISTS(fn), and the matching binding in opensslshim.h must be a
// LIGHTUP_FUNCTION, so that the shim degrades gracefully (throwing a managed exception
// rather than failing to load) once these symbols are actually removed in a future
// OpenSSL release (4.0).
//
// Each family below is gated on the matching HAVE_OPENSSL_*_DEPRECATED probe emitted by
// configure.cmake into pal_crypto_config.h. The probe compiles a reference to the family
// under the same API-compat level the shim is built with, so a section is only re-declared
// when the real headers do NOT already declare it -- this both future-proofs the build
// against involuntary removal and avoids clashing with the real declarations in a normal
// build.

#pragma once
#include "pal_types.h"
#include "pal_crypto_config.h"

// --- HMAC (pal_hmac.c) ---
#if !HAVE_OPENSSL_HMAC_DEPRECATED
// Compile-only support: these bindings intentionally remain REQUIRED_FUNCTION and are
// called unconditionally. Making HMAC survive the removal of these symbols on OpenSSL
// 4.0 (via EVP_MAC or API_EXISTS gating) is deferred to a separate effort. The
// prototypes below only exist so the shim keeps building once the deprecated-removal
// flag is enabled. HMAC_CTX and ENGINE typedefs are not deprecated and remain available.
HMAC_CTX* HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX* ctx);
int HMAC_CTX_copy(HMAC_CTX* dctx, HMAC_CTX* sctx);
int HMAC_Init_ex(HMAC_CTX* ctx, const void* key, int len, const EVP_MD* md, ENGINE* impl);
int HMAC_Update(HMAC_CTX* ctx, const unsigned char* data, size_t len);
int HMAC_Final(HMAC_CTX* ctx, unsigned char* md, unsigned int* len);
#endif // !HAVE_OPENSSL_HMAC_DEPRECATED

// --- Elliptic curve: EC_KEY and deprecated low-level EC ---
#if !HAVE_OPENSSL_ECKEY_DEPRECATED
// (pal_eckey.c, pal_ecc_import_export.c, pal_evp_pkey_eckey.c)
// The EC_KEY type and its accessors are deprecated in 3.0. They are retained so the
// public EC_KEY-handle interop (ECDsaOpenSsl(IntPtr)/ECDiffieHellmanOpenSsl(IntPtr) and
// the legacy EVP_PKEY export fallback) keeps working on OpenSSL 3.x. Every call site is
// API_EXISTS-guarded and the bindings are LIGHTUP_FUNCTION, so the handle path throws a
// clean managed exception on OpenSSL 4.0 rather than crashing. Only EC_KEY is removed
// from <openssl/types.h> under the flag; EC_GROUP/EC_POINT remain declared.
typedef struct ec_method_st EC_METHOD;
typedef struct ec_key_st EC_KEY;

const EC_METHOD* EC_GFp_mont_method(void);
const EC_METHOD* EC_GFp_simple_method(void);
const EC_METHOD* EC_GF2m_simple_method(void);
EC_GROUP* EC_GROUP_new(const EC_METHOD* meth);
const EC_METHOD* EC_GROUP_method_of(const EC_GROUP* group);
int EC_METHOD_get_field_type(const EC_METHOD* meth);
int EC_GROUP_get_curve_GF2m(const EC_GROUP* group, BIGNUM* p, BIGNUM* a, BIGNUM* b, BN_CTX* ctx);
int EC_GROUP_set_curve_GF2m(EC_GROUP* group, const BIGNUM* p, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx);
int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP* group, EC_POINT* p, const BIGNUM* x, const BIGNUM* y, BN_CTX* ctx);
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP* group, const EC_POINT* p, BIGNUM* x, BIGNUM* y, BN_CTX* ctx);
EC_KEY* EC_KEY_new(void);
EC_KEY* EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY* key);
int EC_KEY_up_ref(EC_KEY* key);
int EC_KEY_check_key(const EC_KEY* key);
int EC_KEY_generate_key(EC_KEY* key);
const EC_GROUP* EC_KEY_get0_group(const EC_KEY* key);
const BIGNUM* EC_KEY_get0_private_key(const EC_KEY* key);
const EC_POINT* EC_KEY_get0_public_key(const EC_KEY* key);
int EC_KEY_set_group(EC_KEY* key, const EC_GROUP* group);
int EC_KEY_set_private_key(EC_KEY* key, const BIGNUM* prv);
int EC_KEY_set_public_key(EC_KEY* key, const EC_POINT* pub);
int EC_KEY_set_public_key_affine_coordinates(EC_KEY* key, BIGNUM* x, BIGNUM* y);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY* pkey, EC_KEY* key);
EC_KEY* EVP_PKEY_get1_EC_KEY(EVP_PKEY* pkey);
#endif // !HAVE_OPENSSL_ECKEY_DEPRECATED

// --- RSA (pal_evp_pkey.c, pal_evp_pkey_rsa.c) ---
#if !HAVE_OPENSSL_RSA_DEPRECATED
// The RSA/RSA_METHOD types and the low-level RSA accessors below are deprecated in 3.0 and
// removed from <openssl/types.h> under the flag. They are retained so the public RSA-handle
// interop (RSAOpenSsl(IntPtr)) and the legacy key-parameter export path keep working on
// OpenSSL 3.x. Mainstream RSA operations use the modern EVP_PKEY path and are unaffected.
// Every call site is API_EXISTS-guarded and the bindings are LIGHTUP_FUNCTION, so the handle
// path throws a clean managed exception on OpenSSL 4.0 rather than crashing.
typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;

int RSA_test_flags(const RSA* r, int flags);
int RSA_meth_get_flags(const RSA_METHOD* meth);
int RSA_get_multi_prime_extra_count(const RSA* r);
const RSA_METHOD* RSA_get_method(const RSA* rsa);
void RSA_get0_key(const RSA* r, const BIGNUM** n, const BIGNUM** e, const BIGNUM** d);
void RSA_get0_factors(const RSA* r, const BIGNUM** p, const BIGNUM** q);
void RSA_get0_crt_params(const RSA* r, const BIGNUM** dmp1, const BIGNUM** dmq1, const BIGNUM** iqmp);
const RSA* EVP_PKEY_get0_RSA(const EVP_PKEY* pkey);
int EVP_PKEY_set1_RSA(EVP_PKEY* pkey, RSA* key);
#endif // !HAVE_OPENSSL_RSA_DEPRECATED

// --- ENGINE (pal_evp_pkey.c) ---
#if !HAVE_OPENSSL_ENGINE_DEPRECATED
// The ENGINE typedef itself is not deprecated (it remains in <openssl/types.h>); only the
// functions below are. They are already LIGHTUP_FUNCTION and every call site is
// API_EXISTS-guarded, degrading to the managed "ENGINE not supported" error on OpenSSL 4.0.
ENGINE* ENGINE_by_id(const char* id);
int ENGINE_init(ENGINE* e);
int ENGINE_finish(ENGINE* e);
int ENGINE_free(ENGINE* e);
EVP_PKEY* ENGINE_load_private_key(ENGINE* e, const char* key_id, UI_METHOD* ui_method, void* callback_data);
EVP_PKEY* ENGINE_load_public_key(ENGINE* e, const char* key_id, UI_METHOD* ui_method, void* callback_data);
#endif // !HAVE_OPENSSL_ENGINE_DEPRECATED

// --- ERR_put_error (used widely to raise OpenSSL errors) ---
#if !HAVE_OPENSSL_ERR_PUT_ERROR
// Compile-only support: ERR_put_error has a FALLBACK_FUNCTION binding (local_ERR_put_error
// in apibridge_30.c) that re-implements it on top of ERR_new/ERR_set_debug/ERR_set_error, so
// it already survives removal at runtime. Under the flag <openssl/err.h> drops the backward-
// compatibility macro, so this prototype restores the declaration the shim needs to build.
void ERR_put_error(int32_t lib, int32_t func, int32_t reason, const char* file, int32_t line);

// The convenience macros and per-function error codes below are dropped from the public
// headers under the flag (the function codes live in <openssl/cryptoerr_legacy.h>, which is
// no longer included, and are all defined to 0 there). Restoring them here keeps the existing
// call sites building; they route through ERR_put_error above, so they inherit the same
// runtime fallback and need no separate binding or API_EXISTS guard.
#define DSA_F_DSA_DO_SIGN 0
#define X509_F_X509_VERIFY_CERT 0
#ifndef OPENSSL_NO_FILENAMES
#define ERR_PUT_error(lib, func, reason, file, line) ERR_put_error(lib, func, reason, file, line)
#else
#define ERR_PUT_error(lib, func, reason, file, line) ERR_put_error(lib, func, reason, NULL, 0)
#endif
#define X509err(f, r) ERR_PUT_error(ERR_LIB_X509, (f), (r), __FILE__, __LINE__)
#endif // !HAVE_OPENSSL_ERR_PUT_ERROR

// --- DSA (pal_dsa.c, pal_evp_pkey_dsa.c) ---
#if !HAVE_OPENSSL_DSA_DEPRECATED
// DSA has no modern EVP replacement in this shim, so it depends entirely on the APIs below,
// which are deprecated in 3.0 and removed (together with the DSA/DSA_METHOD types) in 4.0.
// They are retained so DSA keeps working on OpenSSL 3.x. Every call site is API_EXISTS-guarded
// and the bindings are LIGHTUP_FUNCTION, so DSA operations fail with a managed
// CryptographicException on OpenSSL 4.0 rather than crashing.
typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;

DSA* DSA_new(void);
void DSA_free(DSA* r);
int DSA_up_ref(DSA* r);
int DSA_size(const DSA* dsa);
const DSA_METHOD* DSA_OpenSSL(void);
const DSA_METHOD* DSA_get_method(DSA* d);
int DSA_sign(int type, const unsigned char* dgst, int dlen, unsigned char* sig, unsigned int* siglen, DSA* dsa);
int DSA_verify(int type, const unsigned char* dgst, int dgst_len, const unsigned char* sigbuf, int siglen, DSA* dsa);
int DSA_generate_parameters_ex(DSA* dsa, int bits, const unsigned char* seed, int seed_len, int* counter_ret, unsigned long* h_ret, BN_GENCB* cb);
int DSA_generate_key(DSA* a);
void DSA_get0_pqg(const DSA* d, const BIGNUM** p, const BIGNUM** q, const BIGNUM** g);
int DSA_set0_pqg(DSA* d, BIGNUM* p, BIGNUM* q, BIGNUM* g);
void DSA_get0_key(const DSA* d, const BIGNUM** pub_key, const BIGNUM** priv_key);
int DSA_set0_key(DSA* d, BIGNUM* pub_key, BIGNUM* priv_key);
DSA* EVP_PKEY_get1_DSA(EVP_PKEY* pkey);
int EVP_PKEY_set1_DSA(EVP_PKEY* pkey, DSA* key);
#endif // !HAVE_OPENSSL_DSA_DEPRECATED
