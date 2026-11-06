/* psa_store_ns.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* wolfPSA persistent-key store backend for the bare-metal conformance guest:
 * the same object-at-a-time ITS backend wolfPSA ships for Zephyr, riding the
 * routed SERVICE_ITS client. A key id of zero (an invalid/absent handle, not a
 * real record) reports NOT_AVAILABLE so wolfPSA answers INVALID_HANDLE, not
 * STORAGE_FAILURE. */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <psa_store.h>
#include "psa/internal_trusted_storage.h"

typedef struct WolfpsaNsStore {
    psa_storage_uid_t uid;
    unsigned char*    buf;
    size_t            len;
    size_t            off;
    int               write;
} WolfpsaNsStore;

static psa_storage_uid_t wolfpsa_store_uid(int type, unsigned long id1,
    unsigned long id2)
{
    (void)type;
    (void)id2;
    return (psa_storage_uid_t)id1;
}

int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2, int read,
    int variableSz, void** store)
{
    int ret = WOLFPSA_STORE_OK;
    psa_storage_uid_t uid;
    WolfpsaNsStore* ctx = NULL;
    struct psa_storage_info_t info;
    psa_status_t st;

    (void)variableSz;

    if (store == NULL) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    *store = NULL;

    uid = wolfpsa_store_uid(type, id1, id2);
    if (uid == 0) {
        /* PSA_KEY_ID_NULL is never persisted: report the record absent so an
         * invalid or zero handle becomes INVALID_HANDLE, not STORAGE_FAILURE. */
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }

    if (read) {
        st = psa_its_get_info(uid, &info);
        if (st == PSA_ERROR_DOES_NOT_EXIST) {
            return WOLFPSA_STORE_NOT_AVAILABLE;
        }
        if (st != PSA_SUCCESS) {
            return WOLFPSA_STORE_IO_ERROR;
        }
    }

    ctx = (WolfpsaNsStore*)XMALLOC(sizeof(*ctx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->uid = uid;
    ctx->write = (read == 0);
    if (read) {
        ctx->len = (size_t)info.size;
    }

    *store = ctx;
    return ret;
}

int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2, int read,
    void** store)
{
    return wolfPSA_Store_OpenSz(type, id1, id2, read, 0, store);
}

int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    psa_storage_uid_t uid;
    psa_status_t st;

    uid = wolfpsa_store_uid(type, id1, id2);
    if (uid == 0) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }

    st = psa_its_remove(uid);
    if (st == PSA_ERROR_DOES_NOT_EXIST) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }
    if (st != PSA_SUCCESS) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    return WOLFPSA_STORE_OK;
}

void wolfPSA_Store_Close(void* store)
{
    WolfpsaNsStore* ctx = (WolfpsaNsStore*)store;

    if (ctx != NULL) {
        if (ctx->buf != NULL) {
            wc_ForceZero(ctx->buf, ctx->len);
            XFREE(ctx->buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XMEMSET(ctx, 0, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
}

int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len)
{
    WolfpsaNsStore* ctx = (WolfpsaNsStore*)store;
    psa_status_t st;
    size_t got = 0;

    if (ctx == NULL || ctx->write || buffer == NULL || len < 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if (len == 0) {
        return 0;
    }

    st = psa_its_get(ctx->uid, ctx->off, (size_t)len, buffer, &got);
    if (st != PSA_SUCCESS) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    ctx->off += got;
    return (int)got;
}

int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len)
{
    WolfpsaNsStore* ctx = (WolfpsaNsStore*)store;
    unsigned char* grown;
    psa_status_t st;

    if (ctx == NULL || ctx->write == 0 || buffer == NULL || len < 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    if (len > 0) {
        grown = (unsigned char*)XMALLOC(ctx->len + (size_t)len, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (grown == NULL) {
            return WOLFPSA_STORE_IO_ERROR;
        }
        if (ctx->buf != NULL) {
            XMEMCPY(grown, ctx->buf, ctx->len);
            wc_ForceZero(ctx->buf, ctx->len);
            XFREE(ctx->buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XMEMCPY(grown + ctx->len, buffer, (size_t)len);
        ctx->buf = grown;
        ctx->len += (size_t)len;
    }

    if (ctx->len == 0) {
        return len;
    }

    st = psa_its_set(ctx->uid, ctx->len, ctx->buf, 0);
    if (st != PSA_SUCCESS) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    return len;
}
