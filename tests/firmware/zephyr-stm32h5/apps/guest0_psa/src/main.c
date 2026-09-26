/* main.c
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

/* guest0_psa is the PSA Crypto and Initial Attestation lifecycle test.
 *
 * Exercises three PSA primitives that, with wolfPSA_SetDefaultDevID()
 * pointed at WH_DEV_ID by the wolfpsa module's SYS_INIT hook, traverse:
 *
 *   psa_*()  →  wolfPSA  →  wolfCrypt(WH_DEV_ID)  →  crypto_cb
 *            →  wh_Client_CryptoCb  →  SPM-mediated SERVICE_HSM  →  wolfHSM server
 *
 * Persistent-key + ITS samples need a key-storage backend wolfPSA doesn't
 * yet provide on this port, so this app keeps to volatile-key /
 * stateless ops:
 *   - psa_generate_random()  → wolfHSM RNG
 *   - psa_hash_compute(SHA-256)  → wolfHSM SHA-256
 *   - psa_cipher_encrypt(AES-CTR, volatile key)  → wolfHSM AES
 *
 * The runner's `--uarts` mode asserts on the corresponding LOG lines.
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/tee.h>
#include <zephyr/logging/log.h>

#include <psa/crypto.h>
#include <psa/initial_attestation.h>

#include <wolftrust/attestation.h>
#include <wolftrust/zephyr/client.h>

#include "attestation_verify.h"

/* The hsmattackneg probe drives the raw wolfHSM client; only that probe
 * build (hsm engine) links the client, so the headers gate with it. */
#if defined(WT_HSM_ATTACK_PROBE)
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_nvm.h"
#include "wolftrust/services/hsm.h"
#endif

LOG_MODULE_REGISTER(guest0_psa, LOG_LEVEL_INF);

/* SWD ground-truth progress latch: guest0 and guest1 share USART3, so their
 * banners interleave char-by-char and a UART grep is unreliable on silicon.
 * Each milestone ORs its bit here; the hardware runner reads the word over
 * SWD instead of the console. WT_LC_ALL means the full lifecycle ran. */
volatile uint32_t g_guest0_lifecycle __attribute__((used));
#define WT_LC_TEE     0x001u
#define WT_LC_CRYPTO  0x002u
#define WT_LC_ITS     0x004u
#define WT_LC_PS      0x008u
#define WT_LC_KEYOPS  0x010u
#define WT_LC_SHAKAT  0x020u
#define WT_LC_COSE    0x040u
#define WT_LC_DONE    0x080u
#define WT_LC_ALL     0x0FFu

#define WOLFTRUST_FN_HSM_CANCEL 2u
#define WOLFTRUST_FN_FFM_CONNECT 3u
#define WOLFTRUST_FN_FFM_CALL    4u
#define WOLFTRUST_FN_FFM_CLOSE   5u
#define WT_ITS_SID    4099u
#define WT_PS_SID     4100u
#define WT_SERVICE_HSM_SID 4102u

#ifndef WT_EXPECTED_MEASUREMENT_HEX
#define WT_EXPECTED_MEASUREMENT_HEX ""
#endif

#ifndef WT_EXPECTED_LIFECYCLE
#define WT_EXPECTED_LIFECYCLE 0x3000u
#endif

#define WT_PSA_LIFECYCLE_SECURED 0x3000u

/* NS PSA FF-M client API from the OS-neutral client core (P7-S2):
 * psa_connect/psa_call/psa_close/psa_framework_version over the CMSE veneers,
 * no Zephyr TEE-subsystem dependency (closes #16 for the FF-M path). */
#include "psa/client.h"

#if defined(WT_RUN_CONFORMANCE)
/* Arm psa-arch-tests val NSPE entry (P3a-4a). */
extern int32_t val_entry(void);
#endif

/* Route the guest's existing tee_invoke_func-shaped FF-M calls straight to the
 * neutral psa_* client instead of through the Zephyr TEE driver. Same param
 * layout the driver used, so every call site and marker is preserved. */
static int wt_tee_invoke(struct tee_invoke_func_arg *arg, unsigned int num,
			 struct tee_param *param)
{
	psa_invec in;
	psa_outvec out;
	uint32_t in_len;
	uint32_t out_len;

	if (arg == NULL) {
		return -1;
	}
	switch (arg->func) {
	case WOLFTRUST_FN_FFM_CONNECT:
		if (num < 1u) {
			return -1;
		}
		arg->ret = (uint32_t)psa_connect((uint32_t)param[0].a,
						 (uint32_t)param[0].b);
		break;
	case WOLFTRUST_FN_FFM_CALL:
		if (num < 2u) {
			return -1;
		}
		in.base = (const void *)(uintptr_t)param[0].c;
		in_len = (uint32_t)param[1].a;
		in.len = in_len;
		out.base = (void *)(uintptr_t)param[1].b;
		out_len = (uint32_t)param[1].c;
		out.len = out_len;
		arg->ret = (uint32_t)psa_call((psa_handle_t)param[0].a,
			(int32_t)param[0].b,
			(in_len != 0u) ? &in : NULL, (in_len != 0u) ? 1u : 0u,
			(out_len != 0u) ? &out : NULL, (out_len != 0u) ? 1u : 0u);
		break;
	case WOLFTRUST_FN_FFM_CLOSE:
		if (num < 1u) {
			return -1;
		}
		psa_close((psa_handle_t)param[0].a);
		arg->ret = 0u;
		break;
	default:
		return -1;
	}
	return 0;
}

/* Mirror guest0's TEE-driver smoke so the runner's existing TEE assertions
 * stay green and we don't need a second runner mode. */
static void exercise_tee_driver(void)
{
	const struct device *tee = DEVICE_DT_GET_ANY(wolfssl_wolftrust_tee);
	struct tee_version_info ver;
	struct tee_invoke_func_arg arg;
	uint32_t fw;
	int rc;

	if (tee == NULL || !device_is_ready(tee)) {
		LOG_WRN("wolftrust TEE device not present/ready");
		return;
	}
	rc = tee_get_version(tee, &ver);
	if (rc != 0) {
		LOG_WRN("tee_get_version rc=%d", rc);
		return;
	}
	LOG_INF("tee impl_id=0x%08x gen_caps=0x%x", ver.impl_id, ver.gen_caps);

	memset(&arg, 0, sizeof(arg));
	arg.func = WOLFTRUST_FN_HSM_CANCEL;
	rc = tee_invoke_func(tee, &arg, 0, NULL);
	LOG_INF("tee_invoke_func(cancel) rc=%d ret=0x%x", rc, arg.ret);

	fw = psa_framework_version();
	if (fw == 0x0100u)
		LOG_INF("wolfTrust FF-M psa_framework_version=0x%04x", fw);
	else
		LOG_ERR("wolfTrust FF-M psa_framework_version unexpected=0x%04x", fw);
}

/* The SHA-256 KAT now traverses the single mediated path — psa_hash_compute
 * -> wolfPSA -> wolfCrypt(WH_DEV_ID) -> crypto_cb -> the SPM-mediated
 * SERVICE_HSM relay -> wolfHSM server, not the retired SERVICE_CRYPTO op
 * protocol. Same input and expected digest, so the scenario marker is
 * unchanged. */
static void exercise_ffm_crypto(void)
{
	static const uint8_t input[] =
		"wolfTrust FF-M SERVICE_CRYPTO dispatch test";
	static const uint8_t expected[32] = {
		0x20, 0x03, 0xdf, 0x15, 0x2a, 0x52, 0x8a, 0x06,
		0xc8, 0xd3, 0x48, 0xb8, 0xfa, 0x8b, 0x2f, 0x87,
		0xf7, 0x1f, 0xae, 0xc6, 0x24, 0x6c, 0x7e, 0x72,
		0x8e, 0x27, 0xa4, 0xb5, 0x0a, 0x49, 0x84, 0x66
	};
	uint8_t digest[sizeof(expected)];
	size_t digest_len = 0u;
	psa_status_t st;

	st = psa_hash_compute(PSA_ALG_SHA_256, input, sizeof(input) - 1u,
			      digest, sizeof(digest), &digest_len);
	if (st != PSA_SUCCESS || digest_len != sizeof(expected) ||
	    memcmp(digest, expected, sizeof(expected)) != 0) {
		LOG_ERR("FF-M SERVICE_CRYPTO SHA-256 KAT failed st=%d len=%u",
			(int)st, (unsigned)digest_len);
		return;
	}
	LOG_INF("wolfTrust FF-M mediated crypto dispatch verified");
	g_guest0_lifecycle |= WT_LC_CRYPTO;
}

/* P4-S2: the full storage chain from a real Non-secure guest — NS ->
 * SERVICE_ITS (unprivileged SP) -> SERVICE_VAULT (gated wolfHSM backing) ->
 * flash NVM — three protection domains, every hop through the SPM gate.
 * The wire header layout mirrors wt_its_req_t (uid, flags, offset) with the
 * object data concatenated for SET. */
static void exercise_ffm_its(void)
{
	static const uint8_t payload[] = "wolfTrust ITS on-target probe";
	const struct device *tee = DEVICE_DT_GET_ANY(wolfssl_wolftrust_tee);
	struct tee_invoke_func_arg arg;
	struct tee_param param[2];
	uint8_t setbuf[16 + sizeof(payload)];
	uint8_t getbuf[sizeof(payload)];
	uint64_t uid = 0x57544954u; /* "WTIT" */
	int32_t handle;
	int32_t st;
	int rc;

	if (tee == NULL || !device_is_ready(tee)) {
		LOG_WRN("wolftrust TEE device not present/ready");
		return;
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CONNECT;
	param[0].a = WT_ITS_SID;
	param[0].b = 1u;
	rc = wt_tee_invoke(&arg, 1, param);
	handle = (int32_t)arg.ret;
	if (rc != 0 || handle <= 0) {
		LOG_ERR("FF-M psa_connect(SERVICE_ITS) failed rc=%d handle=%d",
			rc, handle);
		return;
	}

	memset(setbuf, 0, sizeof(setbuf));
	memcpy(setbuf, &uid, sizeof(uid));
	memcpy(setbuf + 16, payload, sizeof(payload));
	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CALL;
	param[0].a = (uint64_t)handle;
	param[0].b = 1u; /* WT_ITS_OP_SET */
	param[0].c = (uint64_t)(uintptr_t)setbuf;
	param[1].a = sizeof(setbuf);
	rc = wt_tee_invoke(&arg, 2, param);
	st = (int32_t)arg.ret;
	if (rc != 0 || st != 0) {
		LOG_ERR("psa_its_set via SERVICE_ITS failed rc=%d st=%d",
			rc, st);
	} else {
		memset(getbuf, 0, sizeof(getbuf));
		memset(&arg, 0, sizeof(arg));
		memset(param, 0, sizeof(param));
		arg.func = WOLFTRUST_FN_FFM_CALL;
		param[0].a = (uint64_t)handle;
		param[0].b = 2u; /* WT_ITS_OP_GET */
		param[0].c = (uint64_t)(uintptr_t)setbuf;
		param[1].a = 16u; /* header only */
		param[1].b = (uint64_t)(uintptr_t)getbuf;
		param[1].c = sizeof(getbuf);
		rc = wt_tee_invoke(&arg, 2, param);
		st = (int32_t)arg.ret;
		if (rc != 0 || st != 0) {
			LOG_ERR("psa_its_get via SERVICE_ITS failed rc=%d "
				"st=%d", rc, st);
		} else if (memcmp(getbuf, payload, sizeof(payload)) != 0) {
			LOG_ERR("wolfTrust ITS get returned wrong data");
		} else {
			LOG_INF("wolfTrust ITS set/get verified");
			g_guest0_lifecycle |= WT_LC_ITS;
		}
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CLOSE;
	param[0].a = (uint64_t)handle;
	(void)wt_tee_invoke(&arg, 1, param);
}

/* P4-S3: the sealed-storage round trip. Same wire as ITS, but SERVICE_PS
 * routes each object through the confined vault partition, so a clean
 * set/get proves seal + rollback-counter + unseal end to end on target. */
static void exercise_ffm_ps(void)
{
	static const uint8_t payload[] = "wolfTrust PS on-target secret";
	const struct device *tee = DEVICE_DT_GET_ANY(wolfssl_wolftrust_tee);
	struct tee_invoke_func_arg arg;
	struct tee_param param[2];
	uint8_t setbuf[16 + sizeof(payload)];
	uint8_t getbuf[sizeof(payload)];
	uint64_t uid = 0x57545053u; /* "WTPS" */
	int32_t handle;
	int32_t st;
	int rc;

	if (tee == NULL || !device_is_ready(tee)) {
		LOG_WRN("wolftrust TEE device not present/ready");
		return;
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CONNECT;
	param[0].a = WT_PS_SID;
	param[0].b = 1u;
	rc = wt_tee_invoke(&arg, 1, param);
	handle = (int32_t)arg.ret;
	if (rc != 0 || handle <= 0) {
		LOG_ERR("FF-M psa_connect(SERVICE_PS) failed rc=%d handle=%d",
			rc, handle);
		return;
	}

	memset(setbuf, 0, sizeof(setbuf));
	memcpy(setbuf, &uid, sizeof(uid));
	memcpy(setbuf + 16, payload, sizeof(payload));
	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CALL;
	param[0].a = (uint64_t)handle;
	param[0].b = 1u; /* WT_ITS_OP_SET */
	param[0].c = (uint64_t)(uintptr_t)setbuf;
	param[1].a = sizeof(setbuf);
	rc = wt_tee_invoke(&arg, 2, param);
	st = (int32_t)arg.ret;
	if (rc != 0 || st != 0) {
		LOG_ERR("psa_ps_set via SERVICE_PS failed rc=%d st=%d",
			rc, st);
	} else {
		memset(getbuf, 0, sizeof(getbuf));
		memset(&arg, 0, sizeof(arg));
		memset(param, 0, sizeof(param));
		arg.func = WOLFTRUST_FN_FFM_CALL;
		param[0].a = (uint64_t)handle;
		param[0].b = 2u; /* WT_ITS_OP_GET */
		param[0].c = (uint64_t)(uintptr_t)setbuf;
		param[1].a = 16u; /* header only */
		param[1].b = (uint64_t)(uintptr_t)getbuf;
		param[1].c = sizeof(getbuf);
		rc = wt_tee_invoke(&arg, 2, param);
		st = (int32_t)arg.ret;
		if (rc != 0 || st != 0) {
			LOG_ERR("psa_ps_get via SERVICE_PS failed rc=%d "
				"st=%d", rc, st);
		} else if (memcmp(getbuf, payload, sizeof(payload)) != 0) {
			LOG_ERR("wolfTrust PS get returned wrong data");
		} else {
			LOG_INF("wolfTrust PS sealed set/get verified");
			g_guest0_lifecycle |= WT_LC_PS;
		}
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CLOSE;
	param[0].a = (uint64_t)handle;
	(void)wt_tee_invoke(&arg, 1, param);
}

#if defined(WT_WRITE_ONCE_RESET_PROBE)
/* WRITE_ONCE-across-reset probe (hardware two-boot, driven by the runner).
 * The object's own existence is the boot-phase detector: the first boot on a
 * blank vault seals a WRITE_ONCE object and latches stage 1; the runner then
 * resets the board; the second boot reads the object back (survived the reset)
 * and confirms it refuses a second set (NONMODIFIABLE) and a remove
 * (NONDESTROYABLE), latching stage 2. The runner reads g_write_once_stage over
 * SWD across both boots. */
volatile uint32_t g_write_once_stage __attribute__((used));

static void exercise_write_once_reset(void)
{
	static const uint8_t value[16] = {
		0x57, 0x4F, 0x4E, 0x43, 0x45, 0x2D, 0x53, 0x55,
		0x52, 0x56, 0x49, 0x56, 0x45, 0x2D, 0x30, 0x31
	};
	const struct device *tee = DEVICE_DT_GET_ANY(wolfssl_wolftrust_tee);
	struct tee_invoke_func_arg arg;
	struct tee_param param[2];
	uint8_t setbuf[16 + sizeof(value)];
	uint8_t getbuf[sizeof(value)];
	uint64_t uid = 0x57574F4Eu; /* "WWON" */
	uint32_t flags = 0x1u;      /* WT_VAULT_FLAG_WRITE_ONCE */
	int32_t handle;
	int32_t st;
	int ok;
	int rc;

	if (tee == NULL || !device_is_ready(tee)) {
		g_write_once_stage = 0xEu;
		return;
	}
	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CONNECT;
	param[0].a = WT_PS_SID;
	param[0].b = 1u;
	rc = wt_tee_invoke(&arg, 1, param);
	handle = (int32_t)arg.ret;
	if (rc != 0 || handle <= 0) {
		g_write_once_stage = 0xEu;
		return;
	}

	memset(setbuf, 0, sizeof(setbuf));
	memcpy(setbuf, &uid, sizeof(uid));
	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CALL;
	param[0].a = (uint64_t)handle;
	param[0].b = 2u; /* WT_ITS_OP_GET */
	param[0].c = (uint64_t)(uintptr_t)setbuf;
	param[1].a = 16u;
	param[1].b = (uint64_t)(uintptr_t)getbuf;
	param[1].c = sizeof(getbuf);
	rc = wt_tee_invoke(&arg, 2, param);
	st = (int32_t)arg.ret;

	if (rc == 0 && st == 0) {
		ok = (memcmp(getbuf, value, sizeof(value)) == 0);
		memset(setbuf, 0, sizeof(setbuf));
		memcpy(setbuf, &uid, sizeof(uid));
		memcpy(setbuf + 8, &flags, sizeof(flags));
		memcpy(setbuf + 16, value, sizeof(value));
		memset(&arg, 0, sizeof(arg));
		memset(param, 0, sizeof(param));
		arg.func = WOLFTRUST_FN_FFM_CALL;
		param[0].a = (uint64_t)handle;
		param[0].b = 1u; /* WT_ITS_OP_SET must be refused */
		param[0].c = (uint64_t)(uintptr_t)setbuf;
		param[1].a = sizeof(setbuf);
		(void)wt_tee_invoke(&arg, 2, param);
		if ((int32_t)arg.ret == 0) {
			ok = 0;
		}
		memset(setbuf, 0, sizeof(setbuf));
		memcpy(setbuf, &uid, sizeof(uid));
		memset(&arg, 0, sizeof(arg));
		memset(param, 0, sizeof(param));
		arg.func = WOLFTRUST_FN_FFM_CALL;
		param[0].a = (uint64_t)handle;
		param[0].b = 4u; /* WT_ITS_OP_REMOVE must be refused */
		param[0].c = (uint64_t)(uintptr_t)setbuf;
		param[1].a = 16u;
		(void)wt_tee_invoke(&arg, 2, param);
		if ((int32_t)arg.ret == 0) {
			ok = 0;
		}
		g_write_once_stage = ok ? 2u : 0xEu;
		LOG_INF("wolfTrust WRITE_ONCE reset survival %s",
			ok ? "verified" : "FAILED");
	} else {
		memset(setbuf, 0, sizeof(setbuf));
		memcpy(setbuf, &uid, sizeof(uid));
		memcpy(setbuf + 8, &flags, sizeof(flags));
		memcpy(setbuf + 16, value, sizeof(value));
		memset(&arg, 0, sizeof(arg));
		memset(param, 0, sizeof(param));
		arg.func = WOLFTRUST_FN_FFM_CALL;
		param[0].a = (uint64_t)handle;
		param[0].b = 1u; /* WT_ITS_OP_SET */
		param[0].c = (uint64_t)(uintptr_t)setbuf;
		param[1].a = sizeof(setbuf);
		rc = wt_tee_invoke(&arg, 2, param);
		st = (int32_t)arg.ret;
		g_write_once_stage = (rc == 0 && st == 0) ? 1u : 0xEu;
		LOG_INF("wolfTrust WRITE_ONCE seeded st=%d", (int)st);
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CLOSE;
	param[0].a = (uint64_t)handle;
	(void)wt_tee_invoke(&arg, 1, param);
}
#endif /* WT_WRITE_ONCE_RESET_PROBE */

#if defined(WT_HSM_ATTACK_PROBE)
/* Compromised-guest probe: forge a COMM_INIT claiming the attestation-reserved
 * client_id (WH_CLIENT_ID_MAX) and try to sign with the committed IAK (key
 * 0xF0), then try an NVM-group read of the rollback table (0x0122). Both must
 * fail; the guest's own crypto must still work. */
extern whClientContext *wolfhsm_guest_client(void);

volatile uint32_t g_hsm_attack_probe __attribute__((used));
#define WT_HSM_ATTACK_IAK_REFUSED   0x1u
#define WT_HSM_ATTACK_NVM_REFUSED   0x2u
#define WT_HSM_ATTACK_OWN_NS_OK     0x4u
#define WT_HSM_ATTACK_ALL           0x7u
/* IAK key index (WT_HSM_ATTEST_KEY_ID, private to the secure runtime). */
#define WT_HSM_ATTACK_IAK_KEY_ID    0xF0u

static void exercise_hsm_attack_probe(void)
{
    whClientContext *ctx = wolfhsm_guest_client();
    ecc_key key;
    uint8_t hash[32];
    uint8_t sig[72];
    uint16_t sigLen = (uint16_t)sizeof(sig);
    uint8_t nvmbuf[16];
    uint8_t rngbuf[16];
    uint16_t rGroup = 0u;
    uint16_t rAction = 0u;
    uint16_t rSize = 0u;
    int guard2 = 0;
    uint32_t outClientId = 0;
    uint32_t outServerId = 0;
    psa_status_t st;
    int rc;

    if (ctx == NULL) {
        LOG_ERR("hsmattackneg no wolfHSM client context");
        return;
    }

    ctx->comm->client_id = WH_CLIENT_ID_MAX;
    do {
        rc = wh_Client_CommInitRequest(ctx);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == WH_ERROR_OK) {
        do {
            rc = wh_Client_CommInitResponse(ctx, &outClientId, &outServerId);
        } while (rc == WH_ERROR_NOTREADY);
    }
    LOG_INF("hsmattackneg forged COMM_INIT client_id=%u rc=%d",
        (unsigned)outClientId, rc);

    (void)memset(hash, 0x42, sizeof(hash));
    (void)wc_ecc_init(&key);
    rc = wh_Client_EccSetKeyId(&key, WT_HSM_ATTACK_IAK_KEY_ID);
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_EccSign(ctx, &key, hash, (uint16_t)sizeof(hash),
            sig, &sigLen);
    }
    wc_ecc_free(&key);
    if (rc != WH_ERROR_OK) {
        LOG_INF("hsmattackneg IAK sign refused rc=%d", rc);
        g_hsm_attack_probe |= WT_HSM_ATTACK_IAK_REFUSED;
    } else {
        LOG_ERR("hsmattackneg IAK sign SUCCEEDED (should have been refused)");
    }

    /* A raw NVM-group request must be refused by the relay before it reaches
     * the server; the relay rejects on the message group alone, so the
     * payload only needs the targeted rollback-table id. */
    (void)memset(nvmbuf, 0, sizeof(nvmbuf));
    nvmbuf[0] = (uint8_t)(WT_HSM_ROLLBACK_TABLE_ID & 0xFFu);
    nvmbuf[1] = (uint8_t)((WT_HSM_ROLLBACK_TABLE_ID >> 8) & 0xFFu);
    rc = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_NVM,
        WH_MESSAGE_NVM_ACTION_READ, (uint16_t)sizeof(nvmbuf), nvmbuf);
    if (rc == WH_ERROR_OK) {
        guard2 = 1000;
        do {
            rc = wh_Client_RecvResponse(ctx, &rGroup, &rAction, &rSize,
                (uint16_t)sizeof(nvmbuf), nvmbuf);
        } while (rc == WH_ERROR_NOTREADY && guard2-- > 0);
    }
    if (rc != WH_ERROR_OK) {
        LOG_INF("hsmattackneg rollback NVM group refused rc=%d", rc);
        g_hsm_attack_probe |= WT_HSM_ATTACK_NVM_REFUSED;
    } else {
        LOG_ERR("hsmattackneg rollback NVM group SUCCEEDED (should have been refused)");
    }

    st = psa_generate_random(rngbuf, sizeof(rngbuf));
    if (st == PSA_SUCCESS) {
        LOG_INF("hsmattackneg own-namespace crypto still works");
        g_hsm_attack_probe |= WT_HSM_ATTACK_OWN_NS_OK;
    } else {
        LOG_ERR("hsmattackneg own-namespace crypto FAILED st=%d", (int)st);
    }
}
#endif /* WT_HSM_ATTACK_PROBE */

/* Key-ops now ride the single mediated path: wolfPSA generates a volatile
 * P-256 key pair whose private part lives only inside the wolfHSM server, signs
 * a digest, verifies it, and refuses a tampered digest. Same marker as the
 * retired SERVICE_CRYPTO vault probe. */
static void exercise_ffm_keys(void)
{
	static const uint8_t digest[32] = {
		0x57, 0x54, 0x4B, 0x56, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C
	};
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key = PSA_KEY_ID_NULL;
	uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(256)];
	uint8_t tampered[sizeof(digest)];
	size_t sig_len = 0u;
	psa_status_t st;
	int ok = 1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
					  PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_bits(&attr, 256);

	st = psa_generate_key(&attr, &key);
	if (st != PSA_SUCCESS) {
		LOG_ERR("key generate failed st=%d", (int)st);
		return;
	}

	st = psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest,
			   sizeof(digest), sig, sizeof(sig), &sig_len);
	if (st != PSA_SUCCESS) {
		LOG_ERR("key sign failed st=%d", (int)st);
		ok = 0;
	}

	if (ok) {
		st = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				     digest, sizeof(digest), sig, sig_len);
		if (st != PSA_SUCCESS) {
			LOG_ERR("key verify failed st=%d", (int)st);
			ok = 0;
		}
	}

	if (ok) {
		memcpy(tampered, digest, sizeof(tampered));
		tampered[0] ^= 0x01u;
		st = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				     tampered, sizeof(tampered), sig, sig_len);
		if (st != PSA_ERROR_INVALID_SIGNATURE) {
			LOG_ERR("tampered verify not refused st=%d", (int)st);
			ok = 0;
		}
	}

	if (ok) {
		LOG_INF("wolfTrust key-ops sign/verify verified");
		g_guest0_lifecycle |= WT_LC_KEYOPS;
	}

	(void)psa_destroy_key(key);
}

/* On-target key-isolation negative over the single mediated path (WT-FFM-0046):
 * a signature produced under key A must not verify under key B — there is no
 * cross-key oracle. Two volatile P-256 keys are generated in the wolfHSM
 * server; A signs a digest, A verifies it, and B rejects A's signature. */
static void exercise_ffm_key_negatives(void)
{
	static const uint8_t digest[32] = {
		0x4E, 0x45, 0x47, 0x41, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C
	};
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_a = PSA_KEY_ID_NULL;
	psa_key_id_t key_b = PSA_KEY_ID_NULL;
	uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(256)];
	size_t sig_len = 0u;
	psa_status_t st;
	int ok = 1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
					  PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_bits(&attr, 256);

	st = psa_generate_key(&attr, &key_a);
	if (st != PSA_SUCCESS) {
		LOG_ERR("negatives key A generate failed st=%d", (int)st);
		return;
	}
	st = psa_generate_key(&attr, &key_b);
	if (st != PSA_SUCCESS) {
		LOG_ERR("negatives key B generate failed st=%d", (int)st);
		(void)psa_destroy_key(key_a);
		return;
	}

	st = psa_sign_hash(key_a, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest,
			   sizeof(digest), sig, sizeof(sig), &sig_len);
	if (st != PSA_SUCCESS) {
		LOG_ERR("negatives sign under A failed st=%d", (int)st);
		ok = 0;
	}

	if (ok) {
		st = psa_verify_hash(key_a, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				     digest, sizeof(digest), sig, sig_len);
		if (st != PSA_SUCCESS) {
			LOG_ERR("negatives verify under A failed st=%d",
				(int)st);
			ok = 0;
		}
	}

	if (ok) {
		st = psa_verify_hash(key_b, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				     digest, sizeof(digest), sig, sig_len);
		if (st != PSA_ERROR_INVALID_SIGNATURE) {
			LOG_ERR("cross-key verify under B not refused st=%d",
				(int)st);
			ok = 0;
		}
	}

	if (ok) {
		LOG_INF("wolfTrust key negatives verified");
	}

	(void)psa_destroy_key(key_a);
	(void)psa_destroy_key(key_b);
}

/* Item 9: FF-M IPC negatives on the emulator path. A real Non-secure guest
 * makes two deliberately malformed psa_call requests through the SPM veneer and
 * asserts each is rejected without a fault or stale data — the target-side proof
 * of the handle-integrity and bounded-vector checks host-tested in
 * tests/host/ffm (WT-FFM-0021, WT-FFM-0032). Both errors are recoverable, so
 * this runs inline in the normal lifecycle. */
static void exercise_ffm_negatives(void)
{
	static const uint8_t input[] = "wolfTrust FF-M negative probe";
	const struct device *tee = DEVICE_DT_GET_ANY(wolfssl_wolftrust_tee);
	struct tee_invoke_func_arg arg;
	struct tee_param param[2];
	uint8_t digest[32];
	int32_t handle;
	int32_t st;
	int rc;

	if (tee == NULL || !device_is_ready(tee)) {
		LOG_WRN("wolftrust TEE device not present/ready");
		return;
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CONNECT;
	param[0].a = WT_SERVICE_HSM_SID;
	param[0].b = 1u;
	rc = wt_tee_invoke(&arg, 1, param);
	handle = (int32_t)arg.ret;
	if (rc != 0 || handle <= 0) {
		LOG_ERR("FF-M negative setup connect failed rc=%d handle=%d", rc,
			handle);
		return;
	}

	/* Forged handle: the SPM must not map it to this caller's connection. */
	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CALL;
	param[0].a = (uint64_t)(handle + 0x1000);
	param[0].b = 0u; /* PSA_IPC_CALL */
	param[0].c = (uint64_t)(uintptr_t)input;
	param[1].a = sizeof(input) - 1u;
	param[1].b = (uint64_t)(uintptr_t)digest;
	param[1].c = sizeof(digest);
	rc = wt_tee_invoke(&arg, 2, param);
	st = (int32_t)arg.ret;
	if (rc == 0 && st != 0) {
		LOG_INF("wolfTrust FF-M forged-handle call rejected st=%d", st);
	} else {
		LOG_ERR("FF-M forged-handle call NOT rejected rc=%d st=%d", rc, st);
	}

	/* Oversized input vector: length beyond WT_FFM_TRANSFER_BYTES (1024) is
	 * refused on validation, before any copy. */
	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CALL;
	param[0].a = (uint64_t)handle;
	param[0].b = 0u; /* PSA_IPC_CALL */
	param[0].c = (uint64_t)(uintptr_t)input;
	param[1].a = 2048u; /* > WT_FFM_TRANSFER_BYTES */
	param[1].b = (uint64_t)(uintptr_t)digest;
	param[1].c = sizeof(digest);
	rc = wt_tee_invoke(&arg, 2, param);
	st = (int32_t)arg.ret;
	if (rc == 0 && st != 0) {
		LOG_INF("wolfTrust FF-M oversized-vector call rejected st=%d", st);
	} else {
		LOG_ERR("FF-M oversized-vector call NOT rejected rc=%d st=%d", rc, st);
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CLOSE;
	param[0].a = (uint64_t)handle;
	(void)wt_tee_invoke(&arg, 1, param);
}

static void exercise_psa_rng(void)
{
	uint8_t out[16];
	psa_status_t st;

	st = psa_generate_random(out, sizeof(out));
	LOG_INF("psa_generate_random st=%d first=0x%02x",
		(int)st, (unsigned)out[0]);
}

static void exercise_psa_hash(void)
{
    static const uint8_t input[] =
        "wolfTrust/wolfPSA/wolfHSM/CMSE chain test";
    static const uint8_t expected[32] = {
        0x02, 0x7b, 0x1a, 0xec, 0xb3, 0x27, 0x3a, 0x54,
        0x38, 0x6a, 0xea, 0x85, 0x66, 0x45, 0xa2, 0x6a,
        0xe1, 0xce, 0xc4, 0xdf, 0x1e, 0x00, 0x72, 0x71,
        0xab, 0x5f, 0x10, 0x21, 0x40, 0x57, 0xed, 0x67
    };
    uint8_t digest[sizeof(expected)];
    size_t digestLen = 0u;
    psa_status_t status;

    status = psa_hash_compute(PSA_ALG_SHA_256, input, sizeof(input) - 1u,
        digest, sizeof(digest), &digestLen);
    if ((status != PSA_SUCCESS) || (digestLen != sizeof(expected)) ||
            (memcmp(digest, expected, sizeof(expected)) != 0)) {
        LOG_ERR("psa_hash_compute(SHA-256) KAT failed st=%d len=%u",
            (int)status, (unsigned)digestLen);
        if ((status == PSA_SUCCESS) && (digestLen <= sizeof(digest))) {
            LOG_HEXDUMP_ERR(digest, digestLen, "SHA-256 received");
        }
        return;
    }

    LOG_INF("psa_hash_compute(SHA-256) KAT verified");
    g_guest0_lifecycle |= WT_LC_SHAKAT;
}

static void exercise_psa_cipher(void)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key = PSA_KEY_ID_NULL;
	uint8_t plaintext[16];
	uint8_t ciphertext[PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES,
							   PSA_ALG_CTR,
							   sizeof(plaintext))];
	size_t ct_len = 0;
	psa_status_t st;

	memset(plaintext, 0xA5, sizeof(plaintext));

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
					  PSA_KEY_USAGE_DECRYPT);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_bits(&attr, 128);

	st = psa_generate_key(&attr, &key);
	if (st != PSA_SUCCESS) {
		LOG_WRN("psa_generate_key st=%d", (int)st);
		return;
	}

	st = psa_cipher_encrypt(key, PSA_ALG_CTR,
				 plaintext, sizeof(plaintext),
				 ciphertext, sizeof(ciphertext), &ct_len);
	LOG_INF("psa_cipher_encrypt(AES-CTR) st=%d ct_len=%u",
		(int)st, (unsigned)ct_len);

	(void)psa_destroy_key(key);
}

static void exercise_psa_initial_attestation(void)
{
    uint8_t challenge[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32];
    uint8_t token[640];
    uint8_t undersizedToken[1];
    uint8_t publicKey[65];
    uint8_t tokenMeasurement[32];
    size_t tokenSize = 0u;
    size_t undersizedTokenSize = sizeof(undersizedToken);
    size_t publicKeySize = 0u;
    psa_status_t status;
    uint32_t keyPrefixHigh;
    uint32_t keyPrefixLow;
    uint32_t verifiedLifecycle = 0u;
    int verify;
    size_t i;

    for (i = 0u; i < sizeof(challenge); ++i) {
        challenge[i] = (uint8_t)(0xA0u + i);
    }

    status = psa_initial_attest_get_token_size(sizeof(challenge), &tokenSize);
    if ((status != PSA_SUCCESS) || (tokenSize > sizeof(token))) {
        LOG_INF("psa_initial_attestation unavailable st=%d size=%u",
            (int)status, (unsigned)tokenSize);
        return;
    }

    status = psa_initial_attest_get_token(challenge, sizeof(challenge),
        undersizedToken, sizeof(undersizedToken), &undersizedTokenSize);
    if (status != PSA_ERROR_BUFFER_TOO_SMALL) {
        LOG_ERR("psa_initial_attestation short-buffer mapping failed st=%d",
            (int)status);
        return;
    }
    LOG_INF("psa_initial_attestation short-buffer rejected correctly");

    status = psa_initial_attest_get_token(challenge, sizeof(challenge), token,
        sizeof(token), &tokenSize);
    LOG_INF("psa_initial_attestation st=%d token_len=%u", (int)status,
        (unsigned)tokenSize);
    if (status != PSA_SUCCESS) {
        return;
    }
    LOG_INF("wolfTrust attestation: wolfCOSE COSE_Sign1 signed by wolfHSM");

    status = wolftrust_attestation_get_iak_public_key(publicKey,
        sizeof(publicKey), &publicKeySize);
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_initial_attestation public_key_st=%d", (int)status);
        return;
    }
    keyPrefixHigh = ((uint32_t)publicKey[1] << 24) |
        ((uint32_t)publicKey[2] << 16) |
        ((uint32_t)publicKey[3] << 8) | (uint32_t)publicKey[4];
    keyPrefixLow = ((uint32_t)publicKey[5] << 24) |
        ((uint32_t)publicKey[6] << 16) |
        ((uint32_t)publicKey[7] << 8) | (uint32_t)publicKey[8];
    LOG_INF("wolfTrust attestation: IAK public key prefix=%08x%08x",
        (unsigned)keyPrefixHigh, (unsigned)keyPrefixLow);

    verify = wt_attestation_verify_ex(token, tokenSize, publicKey,
        publicKeySize, challenge, sizeof(challenge),
        WT_EXPECTED_MEASUREMENT_HEX, WT_EXPECTED_LIFECYCLE,
        &verifiedLifecycle, tokenMeasurement);
    if (verify == 0) {
        static const char hexDigits[] = "0123456789abcdef";
        char measurementHex[65];
        unsigned int hexIndex;

        for (hexIndex = 0u; hexIndex < 32u; hexIndex++) {
            measurementHex[hexIndex * 2u] =
                hexDigits[(tokenMeasurement[hexIndex] >> 4) & 0x0Fu];
            measurementHex[(hexIndex * 2u) + 1u] =
                hexDigits[tokenMeasurement[hexIndex] & 0x0Fu];
        }
        measurementHex[64] = '\0';
        LOG_INF("wolfTrust attestation: COSE_Sign1 verified");
        g_guest0_lifecycle |= WT_LC_COSE;
        LOG_INF("wolfTrust attestation: token measurement=%s", measurementHex);
        LOG_INF("attestation verify=0 challenge=ok identity=ok "
            "lifecycle=0x%04x measurement=ok cose=ES256",
            (unsigned)WT_EXPECTED_LIFECYCLE);
#if defined(WT_ATTESTATION_DEVELOPMENT_PROFILE)
        verify = wt_attestation_verify(token, tokenSize, publicKey,
            publicKeySize, challenge, sizeof(challenge),
            WT_EXPECTED_MEASUREMENT_HEX, WT_PSA_LIFECYCLE_SECURED,
            &verifiedLifecycle);
        if (verify == 0) {
            LOG_ERR("secured lifecycle policy accepted development token");
            return;
        }
        LOG_INF("secured lifecycle policy rejected development token");
#endif
    }
    else {
        LOG_ERR("wolfTrust attestation: COSE_Sign1 verification failed rc=%d "
            "expected_lifecycle=0x%04x received_lifecycle=0x%04x", verify,
            (unsigned)WT_EXPECTED_LIFECYCLE, (unsigned)verifiedLifecycle);
    }
}

#if defined(WT_ATTEST_NEG_PROBE)
/* Attestation negatives over the real FF-M IPC path (P5-CI attestneg): the
 * secure side must reject invalid requests with the PSA statuses ARM's
 * test_a001 depends on, and a tampered or misattributed token must fail the
 * guest verify. */
static void exercise_attestation_negatives(void)
{
    uint8_t challenge[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 + 1u];
    uint8_t token[640];
    uint8_t publicKey[65];
    size_t tokenSize = 0u;
    size_t publicKeySize = 0u;
    size_t querySize = 0u;
    uint32_t verifiedLifecycle = 0u;
    psa_status_t status;
    int verify;
    size_t i;

    for (i = 0u; i < sizeof(challenge); ++i) {
        challenge[i] = (uint8_t)(0xC0u + i);
    }

    status = psa_initial_attest_get_token_size(sizeof(challenge), &querySize);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        LOG_ERR("attestneg oversized challenge not rejected st=%d",
            (int)status);
        return;
    }
    LOG_INF("attestneg oversized challenge rejected st=%d", (int)status);

    status = psa_initial_attest_get_token(challenge,
        PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token, 0u, &tokenSize);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        LOG_ERR("attestneg zero token buffer not rejected st=%d",
            (int)status);
        return;
    }
    LOG_INF("attestneg zero token buffer rejected st=%d", (int)status);

    status = psa_initial_attest_get_token(challenge,
        PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token, sizeof(token),
        &tokenSize);
    if (status != PSA_SUCCESS) {
        LOG_ERR("attestneg baseline token failed st=%d", (int)status);
        return;
    }
    status = wolftrust_attestation_get_iak_public_key(publicKey,
        sizeof(publicKey), &publicKeySize);
    if (status != PSA_SUCCESS) {
        LOG_ERR("attestneg public key fetch failed st=%d", (int)status);
        return;
    }

    token[tokenSize - 1u] ^= 0x01u;
    verify = wt_attestation_verify(token, tokenSize, publicKey, publicKeySize,
        challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
        WT_EXPECTED_MEASUREMENT_HEX, WT_EXPECTED_LIFECYCLE,
        &verifiedLifecycle);
    if (verify == 0) {
        LOG_ERR("attestneg tampered token accepted");
        return;
    }
    token[tokenSize - 1u] ^= 0x01u;
    LOG_INF("attestneg tampered token rejected");

    verify = wt_attestation_verify(token, tokenSize, publicKey, publicKeySize,
        challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
        WT_EXPECTED_MEASUREMENT_HEX, 0xEEEEu, &verifiedLifecycle);
    if (verify == 0) {
        LOG_ERR("attestneg lifecycle mismatch accepted");
        return;
    }
    LOG_INF("attestneg lifecycle mismatch rejected");

    LOG_INF("wolfTrust attestation negatives verified");
}
#endif

#if defined(WT_GUEST_FAULT_PROBE)
/* Test-only restart probe: a Non-secure read of Secure RAM raises a SecureFault
 * that escalates to the wolfTrust monitor, exercising the manifest restart_limit
 * on target. Immediate logging flushes the banner before the fault. */
static void wt_guest_fault_probe(void)
{
	volatile const uint32_t *secure_ram = (volatile const uint32_t *)0x30028000u;
	uint32_t sink;

	sink = *secure_ram;
	(void)sink;
}
#endif

#if defined(WT_FWU_PROBE)
/* P6-S4: drive SERVICE_FWU from a Non-secure guest. The unprivileged FWU SP
 * stages the candidate through its privileged SVC flash gate and
 * verifies each block by read-back, so a clean start/write/finish/install
 * proves the isolated update service end to end on target. The wolfBoot swap
 * of the armed image rides the full boot-and-update gate (P6-S6). */
#define WT_FWU_SID        4101u
#define WT_FWU_OP_QUERY   1u
#define WT_FWU_OP_START   2u
#define WT_FWU_OP_WRITE   3u
#define WT_FWU_OP_FINISH  4u
#define WT_FWU_OP_INSTALL 5u
#define WT_FWU_OP_CANCEL  6u
#define WT_FWU_OP_CLEAN   7u
#define WT_FWU_OP_REJECT  8u
#define WT_FWU_READY      0u
#define WT_FWU_STAGED     3u
#define WT_FWU_FAILED     4u

struct wt_fwu_probe_req {
	uint32_t component;
	uint32_t offset;
	uint32_t size;
	uint32_t version;
};

static int32_t wt_fwu_probe_call(const struct device *tee, int32_t handle,
				 uint32_t op, const void *in, uint32_t in_len,
				 void *out, uint32_t out_len)
{
	struct tee_invoke_func_arg arg;
	struct tee_param param[2];
	int rc;

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CALL;
	param[0].a = (uint64_t)handle;
	param[0].b = op;
	param[0].c = (uint64_t)(uintptr_t)in;
	param[1].a = in_len;
	if (out != NULL) {
		param[1].b = (uint64_t)(uintptr_t)out;
		param[1].c = out_len;
	}
	rc = wt_tee_invoke(&arg, 2, param);
	if (rc != 0) {
		return (int32_t)0x7fffffff;
	}
	return (int32_t)arg.ret;
}

static void exercise_ffm_fwu(void)
{
	const struct device *tee = DEVICE_DT_GET_ANY(wolfssl_wolftrust_tee);
	struct tee_invoke_func_arg arg;
	struct tee_param param[2];
	struct wt_fwu_probe_req req;
	uint8_t writebuf[16 + 512];
	uint32_t info[8];
	uint32_t word;
	int ok = 1;
	int32_t handle;
	int32_t st;
	int rc;

	if (tee == NULL || !device_is_ready(tee)) {
		LOG_WRN("wolftrust TEE device not present/ready");
		return;
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CONNECT;
	param[0].a = WT_FWU_SID;
	param[0].b = 1u;
	rc = wt_tee_invoke(&arg, 1, param);
	handle = (int32_t)arg.ret;
	if (rc != 0 || handle <= 0) {
		LOG_ERR("FF-M psa_connect(SERVICE_FWU) failed rc=%d handle=%d",
			rc, handle);
		return;
	}

	/* WT-FWU-0003: a write before start is refused on target. */
	memset(&req, 0, sizeof(req));
	req.size = 32u;
	memset(writebuf, 0, sizeof(writebuf));
	memcpy(writebuf, &req, sizeof(req));
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_WRITE, writebuf,
			       sizeof(writebuf), NULL, 0u);
	if (st == 0) {
		LOG_ERR("wolfTrust FWU write-before-start was not refused");
		ok = 0;
	} else {
		LOG_INF("wolfTrust FWU write-before-start refused");
	}

	memset(&req, 0, sizeof(req));
	req.version = 7u;
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_START, &req, sizeof(req),
			       NULL, 0u);
	if (st != 0) {
		LOG_ERR("wolfTrust FWU start failed st=%d", st);
		ok = 0;
	}

	/* Stage a minimal valid wolfBoot image: the 0x400 header carries the
	 * magic, the payload size, and a version TLV matching the declared
	 * candidate; FINISH parses it, so junk bytes no longer stage. */
	memset(&req, 0, sizeof(req));
	req.offset = 0u;
	req.size = 512u;
	memcpy(writebuf, &req, sizeof(req));
	memset(writebuf + 16, 0xFF, 512u);
	word = 0x464C4F57u; /* "WOLF" */
	memcpy(writebuf + 16, &word, 4u);
	word = 32u; /* payload size */
	memcpy(writebuf + 20, &word, 4u);
	writebuf[24] = 0x01u; /* version TLV: tag 1, len 4, value 7 */
	writebuf[25] = 0x00u;
	writebuf[26] = 0x04u;
	writebuf[27] = 0x00u;
	word = 7u;
	memcpy(writebuf + 28, &word, 4u);
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_WRITE, writebuf,
			       sizeof(writebuf), NULL, 0u);
	if (st != 0) {
		LOG_ERR("wolfTrust FWU write#0 failed st=%d", st);
		ok = 0;
	}

	req.offset = 512u;
	memcpy(writebuf, &req, sizeof(req));
	memset(writebuf + 16, 0xFF, 512u);
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_WRITE, writebuf,
			       sizeof(writebuf), NULL, 0u);
	if (st != 0) {
		LOG_ERR("wolfTrust FWU write#1 failed st=%d", st);
		ok = 0;
	}

	memset(&req, 0, sizeof(req));
	req.offset = 1024u;
	req.size = 32u;
	memcpy(writebuf, &req, sizeof(req));
	memset(writebuf + 16, 0x22, 32u);
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_WRITE, writebuf,
			       16u + 32u, NULL, 0u);
	if (st != 0) {
		LOG_ERR("wolfTrust FWU write#2 failed st=%d", st);
		ok = 0;
	}

	memset(&req, 0, sizeof(req));
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_FINISH, &req, sizeof(req),
			       NULL, 0u);
	if (st != 0) {
		LOG_ERR("wolfTrust FWU finish failed st=%d", st);
		ok = 0;
	}

	/* install arms the swap and asks for a reboot (PSA_SUCCESS_REBOOT = 1). */
	memset(&req, 0, sizeof(req));
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_INSTALL, &req, sizeof(req),
			       NULL, 0u);
	if (st != 1) {
		LOG_ERR("wolfTrust FWU install st=%d (want 1)", st);
		ok = 0;
	}

	memset(&req, 0, sizeof(req));
	memset(info, 0, sizeof(info));
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_QUERY, &req, sizeof(req),
			       info, sizeof(info));
	if (st != 0 || info[0] != WT_FWU_STAGED) {
		LOG_ERR("wolfTrust FWU query st=%d state=%u", st, info[0]);
		ok = 0;
	}

	if (ok) {
		LOG_INF("wolfTrust FWU staged signed-header candidate to update "
			"partition, armed, verified");
	}

	/* PSA FWU 1.0 lifecycle tail: reject disarms the staged swap and
	 * records the error, clean restores READY on target. */
	memset(&req, 0, sizeof(req));
	req.version = (uint32_t)-132; /* PSA_ERROR_GENERIC_ERROR rides version */
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_REJECT, &req, sizeof(req),
			       NULL, 0u);
	if (st != 0) {
		LOG_ERR("wolfTrust FWU reject failed st=%d", st);
		ok = 0;
	}
	memset(&req, 0, sizeof(req));
	memset(info, 0, sizeof(info));
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_QUERY, &req, sizeof(req),
			       info, sizeof(info));
	if (st != 0 || (info[0] & 0xFFu) != WT_FWU_FAILED) {
		LOG_ERR("wolfTrust FWU post-reject query st=%d state=%u", st,
			info[0]);
		ok = 0;
	}
	memset(&req, 0, sizeof(req));
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_CLEAN, &req, sizeof(req),
			       NULL, 0u);
	if (st != 0) {
		LOG_ERR("wolfTrust FWU clean failed st=%d", st);
		ok = 0;
	}
	memset(&req, 0, sizeof(req));
	memset(info, 0, sizeof(info));
	st = wt_fwu_probe_call(tee, handle, WT_FWU_OP_QUERY, &req, sizeof(req),
			       info, sizeof(info));
	if (st != 0 || (info[0] & 0xFFu) != WT_FWU_READY) {
		LOG_ERR("wolfTrust FWU post-clean query st=%d state=%u", st,
			info[0]);
		ok = 0;
	}
	if (ok) {
		LOG_INF("wolfTrust FWU reject disarmed and clean restored READY");
	}

	memset(&arg, 0, sizeof(arg));
	memset(param, 0, sizeof(param));
	arg.func = WOLFTRUST_FN_FFM_CLOSE;
	param[0].a = (uint64_t)handle;
	(void)wt_tee_invoke(&arg, 1, param);
}
#endif

#if defined(WT_MPU_BYPASS_PROBE)
/* Negative isolation proof for the GTZC curtain (WT-FFM-0011): a privileged
 * NS kernel CAN disable its own NS MPU, so the fabric-level MPCBB gating —
 * not the MPU — must keep the peer guest's RAM unreachable. The write is
 * expected to be discarded (RAZ/WI) or to fault; either way the sentinel
 * must not read back. SWD latch: 1 attempted, 2 blocked, 3 leaked. */
volatile uint32_t g_guest0_gtzc_probe;

static void exercise_mpu_bypass_probe(void)
{
	volatile uint32_t *mpu_ctrl_ns = (volatile uint32_t *)0xE000ED94u;
	volatile uint32_t *peer = (volatile uint32_t *)0x20010000u;
	uint32_t readback;

	g_guest0_gtzc_probe = 1u;
	LOG_INF("wolfTrust GTZC bypass probe: attempting peer write");
	*mpu_ctrl_ns = 0u;
	__asm volatile("dsb; isb");
	*peer = 0xDEADBEEFu;
	__asm volatile("dsb");
	readback = *peer;
	if (readback == 0xDEADBEEFu) {
		g_guest0_gtzc_probe = 3u;
		LOG_ERR("wolfTrust GTZC peer write LEAKED");
	} else {
		g_guest0_gtzc_probe = 2u;
		LOG_INF("wolfTrust GTZC peer write blocked (read 0x%08x)",
			readback);
	}
}
#endif

int main(void)
{
	int rc;

	LOG_INF("guest0_psa alive");

#if defined(WT_GUEST_FAULT_PROBE)
	wt_guest_fault_probe();
#endif

	rc = wt_zephyr_client_init("guest0_psa");
	if (rc == 0) {
		LOG_INF("wolfTrust TEE client initialized");
		g_guest0_lifecycle |= WT_LC_TEE;
	} else {
		LOG_WRN("wolfTrust TEE init rc=%d (%s)", rc,
			wt_zephyr_client_status_string(rc));
	}

#if defined(WT_WRITE_ONCE_RESET_PROBE)
	exercise_write_once_reset();
#endif
	exercise_tee_driver();
	exercise_ffm_crypto();
	exercise_ffm_its();
	exercise_ffm_ps();
	exercise_ffm_keys();
	exercise_ffm_key_negatives();
	exercise_ffm_negatives();
#if defined(WT_HSM_ATTACK_PROBE)
	exercise_hsm_attack_probe();
#endif
#if defined(WT_MPU_BYPASS_PROBE)
	exercise_mpu_bypass_probe();
#endif
#if defined(WT_FWU_PROBE)
	exercise_ffm_fwu();
#endif
#if !defined(WT_RUN_CONFORMANCE)
	/* The COSE attestation path needs a deep stack; skip it in the conformance
	 * guest so the Arm val NSPE framework fits guest0's 32 KiB NS window. The
	 * full lifecycle is covered by the positive scenario. */
	exercise_psa_initial_attestation();
#if defined(WT_ATTEST_NEG_PROBE)
	exercise_attestation_negatives();
#endif
	exercise_psa_rng();
	exercise_psa_hash();
	exercise_psa_cipher();
#endif

#if defined(WT_RUN_CONFORMANCE)
	LOG_INF("wolfTrust FF-M conformance: val_entry start");
	(void)val_entry();
#endif

	LOG_INF("guest0_psa done");
	g_guest0_lifecycle |= WT_LC_DONE;

#if defined(WT_M33MU_EXPECT_BKPT)
    __asm volatile("bkpt #0x7f");
#endif

	for (;;) {
		k_sleep(K_SECONDS(1));
	}
}
