/* tpm_tests.c
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

#include <stddef.h>
#include <string.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_wrap.h>

#include "wolftrust/tpm_psa_transport.h"

#include "tpm_tests.h"

#ifndef WT_TPM_APP_NAME
#define WT_TPM_APP_NAME "tpm-app"
#endif

static WOLFTPM2_DEV g_dev;
static WOLFTPM2_KEY g_key;
static TPMT_PUBLIC g_pub;

#define WT_TPM_HASH_FIXED_BYTES   (TPM2_HEADER_SIZE + 2U + 2U + 4U)
#define WT_TPM_HASH_PAYLOAD_BYTES \
    (WT_TPM_FRAME_MAX - WT_TPM_HASH_FIXED_BYTES)
typedef char wt_tpm_hash_frame_nonempty[
    (WT_TPM_FRAME_MAX > WT_TPM_HASH_FIXED_BYTES) ? 1 : -1];
typedef char wt_tpm_hash_payload_fits[
    (WT_TPM_HASH_PAYLOAD_BYTES <= MAX_DIGEST_BUFFER) ? 1 : -1];

static void app_prefix(void)
{
    wt_tpm_puts(WT_TPM_APP_NAME ": ");
}

static void app_line(const char *text)
{
    app_prefix();
    wt_tpm_puts(text);
    wt_tpm_puts("\r\n");
}

static void app_line_i32(const char *text, int value)
{
    app_prefix();
    wt_tpm_puts(text);
    wt_tpm_print_i32(value);
    wt_tpm_puts("\r\n");
}

static int tpm_property_matches(UINT32 property, UINT32 expected)
{
    GetCapability_In in;
    GetCapability_Out out;
    TPML_TAGGED_TPM_PROPERTY* properties;
    TPM_RC rc;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = property;
    in.propertyCount = 1U;
    rc = TPM2_GetCapability(&in, &out);
    properties = &out.capabilityData.data.tpmProperties;

    if (rc != TPM_RC_SUCCESS ||
            out.capabilityData.capability != TPM_CAP_TPM_PROPERTIES ||
            properties->count != 1U ||
            properties->tpmProperty[0].property != property ||
            properties->tpmProperty[0].value != expected) {
        return -1;
    }
    return 0;
}

static int tpm_max_frame_hash(void)
{
    Hash_In in;
    Hash_Out out;
    TPM_RC rc;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.data.size = (UINT16)WT_TPM_HASH_PAYLOAD_BYTES;
    memset(in.data.buffer, 0xA5, in.data.size);
    in.hashAlg = TPM_ALG_SHA256;
    in.hierarchy = TPM_RH_NULL;

    rc = TPM2_Hash(&in, &out);
    return rc == TPM_RC_SUCCESS && out.outHash.size == 32U ? 0 : -1;
}

int wt_tpm_run(void)
{
    static const byte digest[32] = {
        0x77, 0x6f, 0x6c, 0x66, 0x54, 0x72, 0x75, 0x73,
        0x74, 0x20, 0x66, 0x77, 0x54, 0x50, 0x4d, 0x20,
        0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x64,
        0x20, 0x62, 0x79, 0x20, 0x46, 0x46, 0x2d, 0x4d
    };
    byte rnd[16];
    byte sig[80];
    byte pcr[32];
    int sig_size = (int)sizeof(sig);
    int pcr_size = (int)sizeof(pcr);
    int tries;
    int rc = -1;

    for (tries = 0; tries < 50 && rc != 0; tries++) {
        rc = wolfTPM2_Init(&g_dev, NULL, NULL);
        if (rc != 0) {
            wt_tpm_psa_close();
            wt_tpm_wait();
        }
    }
    if (rc != 0) {
        app_line_i32("tpm init FAILED rc=", rc);
        return -1;
    }
    app_line("tpm init ok");

    if (tpm_property_matches(TPM_PT_INPUT_BUFFER, WT_TPM_FRAME_MAX) != 0 ||
            tpm_property_matches(TPM_PT_MAX_COMMAND_SIZE,
                                 WT_TPM_FRAME_MAX) != 0 ||
            tpm_property_matches(TPM_PT_MAX_RESPONSE_SIZE,
                                 WT_TPM_FRAME_MAX) != 0) {
        app_line("tpm frame caps FAILED");
        return -1;
    }
    app_line("tpm frame caps ok");

    if (tpm_max_frame_hash() != 0) {
        app_line("tpm max frame FAILED");
        return -1;
    }
    app_line("tpm max frame ok");

    rc = wolfTPM2_GetRandom(&g_dev, rnd, (word32)sizeof(rnd));
    if (rc != 0) {
        app_line_i32("tpm random FAILED rc=", rc);
        return -1;
    }
    app_line("tpm random ok");

    rc = wolfTPM2_GetKeyTemplate_ECC(&g_pub,
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | TPMA_OBJECT_sign,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc == 0) {
        rc = wolfTPM2_CreatePrimaryKey(&g_dev, &g_key, TPM_RH_OWNER, &g_pub,
                                       NULL, 0);
    }
    if (rc != 0) {
        app_line_i32("tpm primary FAILED rc=", rc);
        return -1;
    }
    app_line("tpm primary ok");

    rc = wolfTPM2_SignHash(&g_dev, &g_key, digest, (int)sizeof(digest), sig,
                           &sig_size);
    if (rc != 0) {
        app_line_i32("tpm sign FAILED rc=", rc);
        return -1;
    }
    app_line("tpm sign ok");

    rc = wolfTPM2_VerifyHash(&g_dev, &g_key, sig, sig_size, digest,
                             (int)sizeof(digest));
    if (rc != 0) {
        app_line_i32("tpm verify FAILED rc=", rc);
        return -1;
    }
    app_line("tpm verify ok");

    rc = wolfTPM2_ExtendPCR(&g_dev, 7, TPM_ALG_SHA256, digest,
                            (int)sizeof(digest));
    if (rc == 0) {
        rc = wolfTPM2_ReadPCR(&g_dev, 7, TPM_ALG_SHA256, pcr, &pcr_size);
    }
    if (rc != 0 || pcr_size != 32) {
        app_line_i32("tpm pcr FAILED rc=", rc);
        return -1;
    }
    app_line("tpm pcr ok");

    (void)wolfTPM2_UnloadHandle(&g_dev, &g_key.handle);
    (void)wolfTPM2_Cleanup(&g_dev);
    app_line("tpm round trip ok");
    return 0;
}
