/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * This source file is part of the Cangjie project, licensed under Apache-2.0
 * with Runtime Library Exception.
 *
 * See https://cangjie-lang.cn/pages/LICENSE for license information.
 */

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "securec.h"
#include "api.h"
#include "opensslSymbols.h"

#define MAX_CERT_COUNT 256

static int CjPemPasswordCb(char* buf, int size, int rwflag, void* userdata)
{
    if (size <= 0) { // invalid size
        return 0;
    }

    // userdata = password zero terminated string
    if (!userdata) {
        return 0;
    }

    size_t len = strlen((const char*)userdata) + 1;
    if (memcpy_s(buf, size, userdata, len) == EOK) {
        return (int)len;
    }

    return 0;
}

BIO* InitBioWithPem(const void* pem, size_t length, ExceptionData* exception, DynMsg* dynMsg)
{
    NOT_NULL_OR_RETURN(exception, pem, NULL, dynMsg);
    CHECK_OR_RETURN(exception, length < (size_t)INT_MAX, NULL, dynMsg);
    CHECK_OR_RETURN(exception, length > 0, NULL, dynMsg);

    BIO* mem = (BIO*)DYN_BIO_new(DYN_BIO_s_mem(dynMsg), dynMsg);
    if (dynMsg && dynMsg->found == false) {
        return NULL;
    }
    if (!mem) {
        HandleError(exception, "Failed to create BIO for PEM", dynMsg);
        return NULL;
    }

    int writeSize = (int)length;
    if (DYN_BIO_write(mem, pem, writeSize, dynMsg) != writeSize) {
        HandleError(exception, "Failed to write PEM to BIO", dynMsg);
        DYN_BIO_vfree(mem, dynMsg);
        return NULL;
    }

    return mem;
}

static X509* LoadCert(const void* pem, size_t length, const char* password, ExceptionData* exception, DynMsg* dynMsg)
{
    NOT_NULL_OR_RETURN(exception, pem, NULL, dynMsg);

    BIO* mem = InitBioWithPem(pem, length, exception, dynMsg);
    if (mem == NULL) {
        return NULL;
    }

    X509* cert = DYN_PEM_read_bio_X509(mem, NULL, CjPemPasswordCb, (void*)password, dynMsg);
    if (cert == NULL) {
        HandleError(exception, "Failed to create X509 certificate: PEM_read_bio_X509() failed", dynMsg);
    }

    DYN_BIO_vfree(mem, dynMsg);

    return cert;
}

static EVP_PKEY* DecodePrivateKey(const void* keyBody, long keySize, ExceptionData* exception, DynMsg* dynMsg)
{
    const unsigned char* dataptr = (const unsigned char*)keyBody;

    EVP_PKEY* pkey = (EVP_PKEY*)DYN_d2i_AutoPrivateKey(NULL, &dataptr, keySize, dynMsg);
    if (pkey == NULL) {
        HandleError(exception,
            "Failed to load private key, it's either corrupted, password is wrong or the format is unsupported",
            dynMsg);
    }

    return pkey;
}

// returns true if the key is for sure a PKCS8 encrypted key
// or false when uncertain
static bool IsEncryptedPkcs8(X509_SIG* p8, DynMsg* dynMsg)
{
    const X509_ALGOR* algorithm = NULL;
    const ASN1_OCTET_STRING* str = NULL;
    DYN_X509_SIG_get0(p8, (const void**)&algorithm, (const void**)&str, dynMsg);
    if (algorithm != NULL) {
        const ASN1_OBJECT* algOid;
        int paramtype;
        const void* param;
        DYN_X509_ALGOR_get0((const void**)&algOid, &paramtype, (const void**)&param, algorithm, dynMsg);
        (void)paramtype;
        (void)param;

        int algNid = DYN_OBJ_obj2nid(algOid, dynMsg);
        if (algNid == NID_pbes2 || algNid == NID_id_scrypt) {
            return true;
        }
    }

    return false;
}

// returns true if the key is for sure a PKCS8 encrypted key
// or false when uncertain
static bool IsEncryptedPkcs8Key(const void* keyBody, size_t length, ExceptionData* exception, DynMsg* dynMsg)
{
    bool encrypted = false;
    BIO* mem = InitBioWithPem(keyBody, length, exception, dynMsg);
    if (mem == NULL) {
        return false;
    }

    X509_SIG* p8 = (X509_SIG*)DYN_d2i_PKCS8_bio(mem, NULL, dynMsg);
    if (p8 != NULL) {
        encrypted = IsEncryptedPkcs8(p8, dynMsg);
        DYN_X509_SIG_free(p8, dynMsg);
    }
    DYN_BIO_vfree(mem, dynMsg);
    return encrypted;
}

static EVP_PKEY* LoadPrivateKey(const void* keyBody, size_t keySize, ExceptionData* exception, DynMsg* dynMsg)
{
    NOT_NULL_OR_RETURN(exception, keyBody, NULL, dynMsg);
    CHECK_OR_RETURN(exception, keySize > 0, NULL, dynMsg);

    bool isEncryptedPkcs8Key = IsEncryptedPkcs8Key(keyBody, keySize, exception, dynMsg);
    if (dynMsg && dynMsg->found == false) {
        return NULL;
    }
    if (isEncryptedPkcs8Key) {
        HandleError(exception, "Failed to load private key, no password specified for encrypted PKCS8 key", dynMsg);
        return NULL;
    }

    CHECK_OR_RETURN(exception, keySize < (size_t)LONG_MAX, NULL, dynMsg);
    return DecodePrivateKey(keyBody, (long)keySize, exception, dynMsg);
}

extern int CJ_TLS_DYN_Add_CA(SSL_CTX* ctx, const void* ca, size_t length, ExceptionData* exception, DynMsg* dynMsg)
{
    EXCEPTION_OR_RETURN(exception, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, ctx, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, ca, 0, dynMsg);
    CHECK_OR_RETURN(exception, length, 0, dynMsg);

    X509* cert = LoadCert(ca, length, 0, exception, dynMsg);
    if (!cert) {
        return 0;
    }

    X509_STORE* store = DYN_SSL_CTX_get_cert_store(ctx, dynMsg);
    if (!store) {
        HandleError(exception, "Failed to add CA: SSL_CTX_get_cert_store() failed", dynMsg);
        DYN_X509_free(cert, dynMsg);
        return 0;
    }

    if (DYN_X509_STORE_add_cert(store, cert, dynMsg) == 0) {
        HandleError(exception, "Failed to add CA: X509_STORE_add_cert() failed", dynMsg);
        DYN_X509_free(cert, dynMsg);
        return 0;
    }

    DYN_X509_free(cert, dynMsg); // decrement refcount

    return 1;
}

static bool TryGetCtxAndCert(
    SSL_CTX* ctx, const void* pem, size_t length, X509** outCert, ExceptionData* exception, DynMsg* dynMsg)
{
    NOT_NULL_OR_RETURN(exception, ctx, false, dynMsg);
    NOT_NULL_OR_RETURN(exception, pem, false, dynMsg);
    CHECK_OR_RETURN(exception, length > 0, false, dynMsg);
    NOT_NULL_OR_RETURN(exception, outCert, false, dynMsg);

    *outCert = LoadCert(pem, length, 0, exception, dynMsg);
    if (*outCert == NULL) {
        return false;
    }

    return true;
}

/**
 * Configure the specified certificate to be used (sent) (should be a single cert)
 */
extern int CJ_TLS_DYN_Use_Cert(SSL_CTX* ctx, const void* pem, size_t length, ExceptionData* exception, DynMsg* dynMsg)
{
    EXCEPTION_OR_RETURN(exception, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, ctx, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, pem, 0, dynMsg);
    CHECK_OR_RETURN(exception, length > 0, 0, dynMsg);

    X509* cert = NULL;
    if (!TryGetCtxAndCert(ctx, pem, length, &cert, exception, dynMsg)) {
        return 0;
    }

    if (DYN_SSL_CTX_use_certificate(ctx, cert, dynMsg) == 0) {
        DYN_X509_free(cert, dynMsg); // free certificate if failed
        HandleError(exception, "Failed to apply certificate: SSL_CTX_use_certificate() failed", dynMsg);
        return 0;
    }
    DYN_X509_free(cert, dynMsg); // decrease count because reference count was increaced internally
    return 1;
}

/**
 * Add a single certificate from the chain (to be sent). Should be invoked after CJ_TLS_DYN_Add_Cert.
 */
extern int CJ_TLS_DYN_Add_Cert(SSL_CTX* ctx, const void* pem, size_t length, ExceptionData* exception, DynMsg* dynMsg)
{
    EXCEPTION_OR_RETURN(exception, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, ctx, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, pem, 0, dynMsg);
    CHECK_OR_RETURN(exception, length > 0, 0, dynMsg);

    X509* cert = NULL;
    if (!TryGetCtxAndCert(ctx, pem, length, &cert, exception, dynMsg)) {
        return 0;
    }

    if (DYN_SSL_CTX_add0_chain_cert(ctx, cert, dynMsg) == 0) {
        HandleError(exception, "Failed to add certificate: SSL_CTX_add0_chain_cert() failed", dynMsg);
        DYN_X509_free(cert, dynMsg);
        return 0;
    }

    return 1;
}

extern int CJ_TLS_DYN_SetPrivateKey(
    SSL_CTX* ctx, const void* keyPem, size_t length, ExceptionData* exception, DynMsg* dynMsg)
{
    EXCEPTION_OR_RETURN(exception, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, ctx, 0, dynMsg);
    NOT_NULL_OR_RETURN(exception, keyPem, 0, dynMsg);
    CHECK_OR_RETURN(exception, length > 0, 0, dynMsg);

    EVP_PKEY* key = LoadPrivateKey(keyPem, length, exception, dynMsg);
    if (!key) {
        return 0;
    }

    if (DYN_SSL_CTX_use_PrivateKey(ctx, key, dynMsg) == 0) {
        HandleError(exception, "Failed to apply private key: SSL_CTX_use_PrivateKey() failed", dynMsg);
        DYN_EVP_PKEY_free(key, dynMsg);
        return 0;
    }

    DYN_EVP_PKEY_free(key, dynMsg); // decrement refcount

    return 1;
}

extern int CJ_TLS_DYN_CheckPrivateKey(SSL_CTX* ctx, const char* file, DynMsg* dynMsg)
{
    if (ctx == NULL) {
        return 0;
    }

    return DYN_SSL_CTX_check_private_key(ctx, dynMsg);
}

static int CertificateVerifyCallbackAlwaysAccepting(X509_STORE_CTX* certStore, void* arg)
{
    (void)arg;

    // we need this for SSL_get0_verified_chain() to work later
    // so consider peer cert and it's provided chain as verified
    // as we are trusting everything peer say
    X509* cert = DYN_X509_STORE_CTX_get0_cert(certStore, NULL);
    if (cert != NULL) {
        STACK_OF(X509)* untrusted = DYN_X509_STORE_CTX_get0_untrusted(certStore, NULL);
        STACK_OF(X509) * verifiedChain;
        if (untrusted == NULL) {
            verifiedChain = (STACK_OF(X509)*)DYN_OPENSSL_sk_new_null(NULL);
        } else {
            // duplicate and increment refcount for every cert in it
            verifiedChain = DYN_X509_chain_up_ref(untrusted, NULL);
        }

        (void)DYN_OPENSSL_sk_insert((void*)verifiedChain, cert, 0, NULL);
        (void)DYN_X509_up_ref(cert, NULL);

        DYN_X509_STORE_CTX_set0_verified_chain(certStore, verifiedChain, NULL);
    }

    DYN_X509_STORE_CTX_set_error(certStore, X509_V_OK, NULL);
    return 1; // always accept
}

extern int CJ_TLS_DYN_SetTrustAll(SSL_CTX* ctx, DynMsg* dynMsg)
{
    if (ctx == NULL) {
        return 0;
    }

    if (!LoadDynFuncCertVerifyCallback(dynMsg)) {
        return 0;
    }
    // we use always accepting callback instead of SSL_VERIFY_NONE
    // because using SSL_VERIFY_NONE on server causes client to not send certificate
    // breaking identification modes
    DYN_SSL_CTX_set_cert_verify_callback(ctx, CertificateVerifyCallbackAlwaysAccepting, NULL, dynMsg);

    return 1;
}

/**
 * Whether client need to identify (send certificate).
 */
extern int CJ_TLS_DYN_SetClientVerifyMode(SSL_CTX* ctx, int required, int verify, DynMsg* dynMsg)
{
    if (ctx == NULL) {
        return 0;
    }

    if (verify == 0 && required == 0) {
        // we are here because TlsClientIdentificationMode = Disabled
        // we don't ask for client certificate so the client will not send it
        // and nothing to verify
        DYN_SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0, dynMsg);
        return 1;
    }

    int flags = SSL_VERIFY_PEER;
    if (required != 0) {
        flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    DYN_SSL_CTX_set_verify(ctx, flags, 0, dynMsg);
    return 1;
}

struct CertChainItem {
    void* cert;
    int size;
};

extern void CJ_TLS_DYN_CertChainFree(struct CertChainItem* result, int i, DynMsg* dynMsg)
{
    if (result == NULL) {
        return;
    }

    for (int before = 0; before < i; before++) {
        void* sub = result[before].cert;
        if (sub != NULL) {
            DYN_CRYPTO_free(sub, dynMsg);
        }
    }
    free(result);
}

static bool EncodeCertTo(struct CertChainItem* result, X509* cert, DynMsg* dynMsg)
{
    unsigned char* ptr = NULL;
    int resultSize = DYN_i2d_X509(cert, &ptr, dynMsg);
    if (resultSize < 0 || ptr == NULL) {
        return false;
    }

    result->cert = ptr;
    result->size = resultSize;

    return true;
}

extern struct CertChainItem* CJ_TLS_DYN_GetPeerCertificate(
    const SSL* ssl, uint32_t* countPtr, ExceptionData* exception, DynMsg* dynMsg)
{
    EXCEPTION_OR_RETURN(exception, NULL, dynMsg);
    NOT_NULL_OR_RETURN(exception, ssl, NULL, dynMsg);
    NOT_NULL_OR_RETURN(exception, countPtr, NULL, dynMsg);

    *countPtr = 0;

    // SSL_get_peer_cert_chain() doesn't return cert itself on server
    // so we use SSL_get0_verified_chain that does always return all
    // the disadvantage is that it only return verified rather than actually sent
    // that is not exactly "fair" as it's not what the peer sent us
    // but it's simpler to implement
    STACK_OF(X509)* chain = (STACK_OF(X509)*)DYN_SSL_get0_verified_chain(ssl, dynMsg);
    if (chain == NULL) {
        // peer certificate may be optional: no error
        return NULL;
    }

    int count = DYN_OPENSSL_sk_num((void*)chain, dynMsg);
    if (count <= 0) {
        return NULL;
    }
    if (count > MAX_CERT_COUNT) {
        HandleError(exception, "Too many certificate entries provided", dynMsg);
        return NULL;
    }

    struct CertChainItem* result = malloc(sizeof(struct CertChainItem) * (size_t)count);
    if (result == NULL) {
        HandleError(exception, "Failed to allocate memory for certificate chain", dynMsg);
        return NULL;
    }

    for (int i = 0; i < count; ++i) {
        X509* cert = (X509*)DYN_OPENSSL_sk_value((void*)chain, i, dynMsg);
        if (cert == NULL) {
            CJ_TLS_DYN_CertChainFree(result, i, dynMsg);
            HandleError(exception, "Failed to get certificate entry", dynMsg);
            return NULL;
        }

        if (!EncodeCertTo(&result[i], cert, dynMsg)) {
            CJ_TLS_DYN_CertChainFree(result, i, dynMsg);
            HandleError(exception, "Failed to decode peer certificate entry", dynMsg);
            return NULL;
        }
    }

    *countPtr = (uint32_t)count;

    return result;
}

extern int CJ_TLS_DYN_SetSecurityLevel(SSL_CTX* ctx, int32_t level, DynMsg* dynMsg)
{
    if (ctx == NULL) {
        return 0;
    }

    /* set the security level to be safe enough */
    DYN_SSL_CTX_set_security_level(ctx, (int)level, dynMsg);

    return 1;
}