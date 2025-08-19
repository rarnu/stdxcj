/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * This source file is part of the Cangjie project, licensed under Apache-2.0
 * with Runtime Library Exception.
 *
 * See https://cangjie-lang.cn/pages/LICENSE for license information.
 */

#ifndef CJ_API_H
#define CJ_API_H

#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "opensslSymbols.h"

#define CJ_EOF 0
#define CJ_FAIL (-1)
#define CJ_NEED_READ (-2)
#define CJ_NEED_WRITE (-3)
#define CJ_OK 1

#define CJTLS_EOF 0
#define CJTLS_FAIL (-1)
#define CJTLS_NEED_READ (-2)
#define CJTLS_NEED_WRITE (-3)
#define CJTLS_OK 1

struct StringArrayResult {
    char** buffer;
    size_t size;
};

struct ByteResult {
    uint8_t* buffer;
    size_t size;
};

struct ByteArrayResult {
    struct ByteResult* buffer;
    size_t size;
};

struct UInt16Result {
    uint16_t* buffer;
    size_t size;
};

#define X509_RESULT_SIZE sizeof(struct StringArrayResult)

typedef struct ExceptionDataS ExceptionData;

typedef struct CipherSuite {
    const char* name;
} CipherSuite;

// this should be syncronized with foreign struct in Cangjie code
typedef struct EncryptedKeyParams {
    char* password;
    const unsigned char* iv;
    size_t ivLength;
    const char* cipherName;
} EncryptedKeyParams;

void X509ExceptionClear(ExceptionData* exception, DynMsg* dynMsg);

bool X509CheckOrFillException(ExceptionData* exception, bool condition, const char* description, DynMsg* dynMsg);

bool X509CheckNotNull(ExceptionData* exception, const void* candidate, const char* name, DynMsg* dynMsg);

void X509HandleError(ExceptionData* exception, const char* fallback, DynMsg* dynMsg);

const char* X509DescribePrivateKey(EVP_PKEY* key, DynMsg* dynMsg);

#define EXCEPTION_OR_RETURN(exception, ret, dynMsg)                                                                    \
    do {                                                                                                               \
        if ((exception) == NULL) {                                                                                     \
            return (ret);                                                                                              \
        };                                                                                                             \
        ExceptionClear(exception, dynMsg);                                                                             \
    } while (0)

#define EXCEPTION_OR_FAIL(exception, dynMsg) EXCEPTION_OR_RETURN((exception), CJTLS_FAIL, dynMsg)

#define NOT_NULL_OR_RETURN(exception, var, ret, dynMsg)                                                                \
    do {                                                                                                               \
        if (!CheckNotNull(exception, (void*)(var), #var, dynMsg))                                                      \
            return (ret);                                                                                              \
    } while (0)

#define NOT_NULL_OR_FAIL(exception, var, dynMsg) NOT_NULL_OR_RETURN((exception), (var), CJTLS_FAIL, dynMsg)

#define CHECK_OR_RETURN(exception, cond, ret, dynMsg)                                                                  \
    do {                                                                                                               \
        if (!CheckOrFillException(exception, (bool)(cond), #cond, dynMsg))                                             \
            return (ret);                                                                                              \
    } while (0)

#define CHECK_OR_FAIL(exception, cond, dynMsg) CHECK_OR_RETURN((exception), (cond), CJTLS_FAIL, dynMsg)

typedef struct ExceptionDataS ExceptionData;

typedef struct TlsCipherSuite {
    const char* name;
} TlsCipherSuite;

void ExceptionClear(ExceptionData* exception, DynMsg* dynMsg);

bool CheckOrFillException(ExceptionData* exception, bool condition, const char* description, DynMsg* dynMsg);

bool CheckNotNull(ExceptionData* exception, const void* candidate, const char* name, DynMsg* dynMsg);

void HandleAlertError(ExceptionData* exception, const char* description, const char* type, DynMsg* dynMsg);

void HandleError(ExceptionData* exception, const char* fallback, DynMsg* dynMsg);

BIO_METHOD* CJ_TLS_BIO_GetMethod(ExceptionData* exception, DynMsg* dynMsg);

int CJ_TLS_BIO_Map(BIO* bio, void* pointer, size_t length, int eof, ExceptionData* exception, DynMsg* dynMsg);

int CJ_TLS_BIO_Unmap(BIO* bio, int eof, ExceptionData* exception, DynMsg* dynMsg);

int NewSessionCallback(SSL* ssl, SSL_SESSION* session);

void SessionReusedCallback(SSL* ssl, SSL_SESSION* session);

BIO* InitBioWithPem(const void* pem, size_t length, ExceptionData* exception, DynMsg* dynMsg);

#endif
