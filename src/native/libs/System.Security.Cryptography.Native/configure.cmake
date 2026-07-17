include(CheckLibraryExists)
include(CheckFunctionExists)
include(CheckSourceCompiles)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
set(CMAKE_REQUIRED_DEFINITIONS -DOPENSSL_API_COMPAT=0x10100000L)

check_function_exists(
    EC_GF2m_simple_method
    HAVE_OPENSSL_EC2M)

check_function_exists(
	SSL_get0_alpn_selected
	HAVE_OPENSSL_ALPN)

check_function_exists(
    EVP_DigestSqueeze
    HAVE_OPENSSL_SHA3_SQUEEZE
)

check_function_exists(
    EVP_PKEY_sign_message_init
    HAVE_OPENSSL_EVP_PKEY_SIGN_MESSAGE_INIT
)

check_source_compiles(C "
#include <openssl/evp.h>
// CodeQL [SM01923] This is a CMake function detection script for the OpenSSL API used to implement the .NET API System.Security.Cryptography.ChaCha20Poly1305, it is not actually using the algorithm here
int main(void) { const EVP_CIPHER* cipher = EVP_chacha20_poly1305(); return 1; }"
HAVE_OPENSSL_CHACHA20POLY1305)

check_source_compiles(C "
#include <openssl/engine.h>
int main(void) { ENGINE_init(NULL); return 1; }"
HAVE_OPENSSL_ENGINE)

# Detect whether the OpenSSL headers, as compiled with THIS build's API-compat level, still
# declare the families of functions that were deprecated in OpenSSL 3.0. When a future OpenSSL
# removes them from the headers -- or the opt-in CRYPTO_VALIDATE_NO_DEPRECATED_OSSL build hides
# them -- these come back 0 and osslcompat_deprecated.h supplies the missing prototypes so the
# shim keeps building. Those prototypes are bound as LIGHTUP_FUNCTIONs with every call site
# API_EXISTS-guarded, so the runtime degrades gracefully once the symbols are actually gone.
#
# The probe must mirror the flags the shim is actually compiled with, and it is compile-only:
# we care whether the declaration is visible, not whether the symbol can be linked (e.g. ENGINE
# may be configured out of libcrypto yet still declared in the headers).
if (CRYPTO_VALIDATE_NO_DEPRECATED_OSSL)
    set(CMAKE_REQUIRED_DEFINITIONS -DOPENSSL_API_COMPAT=0x30000000L -DOPENSSL_NO_DEPRECATED)
else()
    set(CMAKE_REQUIRED_DEFINITIONS -DOPENSSL_API_COMPAT=0x10100000L)
endif()

set(_saved_try_compile_target_type "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# check_source_compiles caches its result by variable name only, ignoring the required
# definitions. Since these probes depend on the API-compat level (which the option can
# change between configures), clear the cached results so they always re-evaluate.
unset(HAVE_OPENSSL_DSA_DEPRECATED CACHE)
unset(HAVE_OPENSSL_ECKEY_DEPRECATED CACHE)
unset(HAVE_OPENSSL_RSA_DEPRECATED CACHE)
unset(HAVE_OPENSSL_ENGINE_DEPRECATED CACHE)
unset(HAVE_OPENSSL_HMAC_DEPRECATED CACHE)
unset(HAVE_OPENSSL_ERR_PUT_ERROR CACHE)

check_source_compiles(C "
#include <openssl/dsa.h>
int test(void) { DSA* d = DSA_new(); DSA_free(d); return 0; }"
HAVE_OPENSSL_DSA_DEPRECATED)

check_source_compiles(C "
#include <openssl/ec.h>
int test(void) { EC_KEY* k = EC_KEY_new(); EC_KEY_free(k); return 0; }"
HAVE_OPENSSL_ECKEY_DEPRECATED)

check_source_compiles(C "
#include <openssl/rsa.h>
int test(void) { const BIGNUM* n; const BIGNUM* e; const BIGNUM* d; RSA_get0_key((const RSA*)0, &n, &e, &d); return 0; }"
HAVE_OPENSSL_RSA_DEPRECATED)

check_source_compiles(C "
#include <openssl/engine.h>
int test(void) { ENGINE* e = ENGINE_by_id(\"\"); ENGINE_free(e); return 0; }"
HAVE_OPENSSL_ENGINE_DEPRECATED)

check_source_compiles(C "
#include <openssl/hmac.h>
int test(void) { HMAC_CTX* c = HMAC_CTX_new(); HMAC_CTX_free(c); return 0; }"
HAVE_OPENSSL_HMAC_DEPRECATED)

check_source_compiles(C "
#include <openssl/err.h>
int test(void) { ERR_put_error(0, 0, 0, \"\", 0); return 0; }"
HAVE_OPENSSL_ERR_PUT_ERROR)

set(CMAKE_TRY_COMPILE_TARGET_TYPE "${_saved_try_compile_target_type}")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pal_crypto_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/pal_crypto_config.h)
