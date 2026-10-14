#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wolfpkcs11/pkcs11.h"

#include "wolftrust/pkcs11_psa_transport.h"
#include "wolftrust/pkcs11/pkcs11_wire.h"

#include "pkcs11_tests.h"

#define WT_PKCS11_SLOT 1UL
#define WT_ARRAY_SIZE(a) ((CK_ULONG)(sizeof(a) / sizeof((a)[0])))

#ifndef WT_PKCS11_APP_NAME
#define WT_PKCS11_APP_NAME "pkcs11-freertos"
#endif

typedef int (*wt_test_fn)(void);

static CK_FUNCTION_LIST_PTR g_fn;
static CK_SESSION_HANDLE g_session = CK_INVALID_HANDLE;
static unsigned int g_passed;
static unsigned int g_failed;
static int g_keep_session;

static CK_UTF8CHAR g_so_pin[] = "wolfTrust-so";
static CK_UTF8CHAR g_user_pin[] = "wolfTrust-user";
static CK_UTF8CHAR g_alt_pin[] = "wolfTrust-alt";
static CK_UTF8CHAR g_token_label[] =
    "wolfTrust HSM token             ";

static CK_BBOOL g_true = CK_TRUE;
static CK_BBOOL g_false = CK_FALSE;
static CK_OBJECT_CLASS g_data_class = CKO_DATA;
static CK_OBJECT_CLASS g_secret_class = CKO_SECRET_KEY;
static CK_OBJECT_CLASS g_public_class = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS g_private_class = CKO_PRIVATE_KEY;
static CK_KEY_TYPE g_aes_type = CKK_AES;
static CK_KEY_TYPE g_generic_type = CKK_GENERIC_SECRET;
static CK_KEY_TYPE g_ec_type = CKK_EC;

static const CK_BYTE g_p256_params[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};
static const CK_BYTE g_digest_input[] = "abc";
static const CK_BYTE g_sha256_abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static void app_prefix(void)
{
    wt_pkcs11_puts(WT_PKCS11_APP_NAME ": ");
}

static void report_case(const char *name, int passed)
{
    app_prefix();
    wt_pkcs11_puts(passed != 0 ? "PASS " : "FAIL ");
    wt_pkcs11_puts(name);
    wt_pkcs11_puts("\r\n");
    if (passed != 0) {
        g_passed++;
    }
    else {
        g_failed++;
    }
}

static void run_case(const char *name, wt_test_fn test)
{
    report_case(name, test() == 0);
}

static int buffer_nonzero(const CK_BYTE *buffer, CK_ULONG length)
{
    CK_ULONG index;
    CK_BYTE value = 0u;

    for (index = 0u; index < length; index++) {
        value |= buffer[index];
    }
    return value != 0u;
}

static int malformed_initialize_rejected(void)
{
    uint8_t request[12];
    uint8_t response[12];
    size_t response_len = 0u;
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;

    wt_pkcs11_writer_init(&writer, request, sizeof(request));
    wt_pkcs11_put_u32(&writer, WT_PKCS11_WIRE_MAGIC);
    wt_pkcs11_put_u32(&writer, WT_PKCS11_WIRE_VERSION);
    wt_pkcs11_put_u32(&writer, WT_P11_INITIALIZE);
    if (writer.error != 0 || wt_pkcs11_psa_call(request, writer.used,
            response, sizeof(response), &response_len) != 0) {
        return -1;
    }
    wt_pkcs11_reader_init(&reader, response, response_len);
    if (wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_MAGIC ||
            wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_VERSION) {
        return -1;
    }
    rv = (CK_RV)wt_pkcs11_get_u32(&reader);
    return reader.error == 0 && reader.used == reader.length &&
           rv == CKR_ARGUMENTS_BAD ? 0 : -1;
}

static int library_initialize(void)
{
    CK_RV rv = CKR_FUNCTION_FAILED;
    unsigned int tries;

    if (C_GetFunctionList(&g_fn) != CKR_OK || g_fn == NULL) {
        return -1;
    }
    if (malformed_initialize_rejected() != 0) {
        return -1;
    }
    for (tries = 0u; tries < 50u; tries++) {
        rv = g_fn->C_Initialize(NULL);
        if (rv == CKR_OK) {
            return 0;
        }
        if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            return -1;
        }
        (void)g_fn->C_Finalize(NULL);
        wt_pkcs11_wait();
    }
    return -1;
}

static int token_login(void)
{
    CK_RV rv;

    rv = g_fn->C_InitToken(WT_PKCS11_SLOT, g_so_pin,
                           (CK_ULONG)(sizeof(g_so_pin) - 1u),
                           g_token_label);
    if (rv != CKR_OK) {
        return -1;
    }
    rv = g_fn->C_OpenSession(WT_PKCS11_SLOT,
                             CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL, NULL, &g_session);
    if (rv != CKR_OK) {
        return -1;
    }
    rv = g_fn->C_Login(g_session, CKU_SO, g_so_pin,
                       (CK_ULONG)(sizeof(g_so_pin) - 1u));
    if (rv != CKR_OK) {
        return -1;
    }
    rv = g_fn->C_InitPIN(g_session, g_user_pin,
                         (CK_ULONG)(sizeof(g_user_pin) - 1u));
    if (rv != CKR_OK || g_fn->C_Logout(g_session) != CKR_OK) {
        return -1;
    }
    rv = g_fn->C_Login(g_session, CKU_USER, g_user_pin,
                       (CK_ULONG)(sizeof(g_user_pin) - 1u));
    return rv == CKR_OK ? 0 : -1;
}

static int suite_setup(void)
{
    if (library_initialize() != 0) {
        return -1;
    }
    if (token_login() != 0) {
        (void)g_fn->C_Finalize(NULL);
        return -1;
    }
    return 0;
}

static int suite_ready(void)
{
    if (g_fn != NULL && g_session != CK_INVALID_HANDLE) {
        return 0;
    }
    return suite_setup();
}

static void suite_cleanup(void)
{
    if (g_fn != NULL) {
        if (g_session != CK_INVALID_HANDLE) {
            (void)g_fn->C_Logout(g_session);
            (void)g_fn->C_CloseSession(g_session);
        }
        (void)g_fn->C_Finalize(NULL);
    }
    g_session = CK_INVALID_HANDLE;
    g_fn = NULL;
}

static int test_library_info(void)
{
    CK_INFO info;

    return g_fn->C_GetInfo(&info) == CKR_OK ? 0 : -1;
}

static int test_slot_list(void)
{
    CK_SLOT_ID slots[65];
    CK_ULONG count = ~(CK_ULONG)0u;
    CK_ULONG index;
    int found = 0;

    if (g_fn->C_GetSlotList(CK_TRUE, NULL, &count) != CKR_OK ||
            count == 0u || count > WT_ARRAY_SIZE(slots)) {
        return -1;
    }
    count = WT_ARRAY_SIZE(slots);
    if (g_fn->C_GetSlotList(CK_TRUE, slots, &count) != CKR_OK) {
        return -1;
    }
    for (index = 0u; index < count; index++) {
        if (slots[index] == WT_PKCS11_SLOT) {
            found = 1;
        }
    }
    return found != 0 ? 0 : -1;
}

static int test_slot_token_info(void)
{
    CK_SLOT_INFO slot_info;
    CK_TOKEN_INFO token_info;

    if (g_fn->C_GetSlotInfo(WT_PKCS11_SLOT, &slot_info) != CKR_OK) {
        return -1;
    }
    return g_fn->C_GetTokenInfo(WT_PKCS11_SLOT, &token_info) == CKR_OK ?
           0 : -1;
}

static int mechanism_present(const CK_MECHANISM_TYPE *list, CK_ULONG count,
                             CK_MECHANISM_TYPE mechanism)
{
    CK_ULONG index;

    for (index = 0u; index < count; index++) {
        if (list[index] == mechanism) {
            return 1;
        }
    }
    return 0;
}

static int test_mechanism_list(void)
{
    CK_MECHANISM_TYPE list[65];
    CK_MECHANISM_INFO info;
    CK_ULONG count = ~(CK_ULONG)0u;

    if (g_fn->C_GetMechanismList(WT_PKCS11_SLOT, NULL, &count) != CKR_OK ||
            count == 0u || count > WT_ARRAY_SIZE(list)) {
        return -1;
    }
    count = WT_ARRAY_SIZE(list);
    if (g_fn->C_GetMechanismList(WT_PKCS11_SLOT, list, &count) != CKR_OK ||
            mechanism_present(list, count, CKM_EC_KEY_PAIR_GEN) == 0 ||
            mechanism_present(list, count, CKM_ECDSA) == 0 ||
            mechanism_present(list, count, CKM_ECDH1_DERIVE) == 0 ||
            mechanism_present(list, count, CKM_AES_KEY_GEN) == 0 ||
            mechanism_present(list, count, CKM_SHA256) == 0) {
        return -1;
    }
    return g_fn->C_GetMechanismInfo(WT_PKCS11_SLOT, CKM_ECDSA, &info) ==
           CKR_OK ? 0 : -1;
}

static int test_session_info(void)
{
    CK_SESSION_INFO info;

    if (g_fn->C_GetSessionInfo(g_session, &info) != CKR_OK) {
        return -1;
    }
    return (info.flags & (CKF_SERIAL_SESSION | CKF_RW_SESSION)) ==
           (CKF_SERIAL_SESSION | CKF_RW_SESSION) ? 0 : -1;
}

static int test_read_only_session(void)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_INFO info;
    CK_RV rv;

    rv = g_fn->C_OpenSession(WT_PKCS11_SLOT, CKF_SERIAL_SESSION,
                             NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = g_fn->C_GetSessionInfo(session, &info);
    }
    if (session != CK_INVALID_HANDLE) {
        (void)g_fn->C_CloseSession(session);
    }
    if (rv != CKR_OK || (info.flags & CKF_RW_SESSION) != 0u) {
        return -1;
    }
    return 0;
}

static int test_pin_change(void)
{
    CK_RV rv;

    rv = g_fn->C_SetPIN(g_session, g_user_pin,
                        (CK_ULONG)(sizeof(g_user_pin) - 1u), g_alt_pin,
                        (CK_ULONG)(sizeof(g_alt_pin) - 1u));
    if (rv != CKR_OK || g_fn->C_Logout(g_session) != CKR_OK) {
        return -1;
    }
    rv = g_fn->C_Login(g_session, CKU_USER, g_alt_pin,
                       (CK_ULONG)(sizeof(g_alt_pin) - 1u));
    if (rv != CKR_OK) {
        return -1;
    }
    rv = g_fn->C_SetPIN(g_session, g_alt_pin,
                        (CK_ULONG)(sizeof(g_alt_pin) - 1u), g_user_pin,
                        (CK_ULONG)(sizeof(g_user_pin) - 1u));
    return rv == CKR_OK ? 0 : -1;
}

static void run_core_suite(void)
{
    report_case("library initialize", library_initialize() == 0);
    if (g_fn == NULL) {
        return;
    }
    run_case("library info", test_library_info);
    run_case("slot enumeration", test_slot_list);
    run_case("slot and token info", test_slot_token_info);
    run_case("mechanism enumeration", test_mechanism_list);
    report_case("token and user login", token_login() == 0);
    if (g_session == CK_INVALID_HANDLE) {
        suite_cleanup();
        return;
    }
    run_case("session info", test_session_info);
    run_case("read-only session", test_read_only_session);
    run_case("PIN change", test_pin_change);
    if (g_keep_session == 0) {
        suite_cleanup();
    }
}

static CK_RV create_data_object(const char *label, CK_BBOOL private_value,
                                CK_OBJECT_HANDLE *object)
{
    CK_BYTE value[] = "wolfTrust PKCS11 object";
    CK_ATTRIBUTE attributes[] = {
        { CKA_CLASS, &g_data_class, sizeof(g_data_class) },
        { CKA_TOKEN, &g_false, sizeof(g_false) },
        { CKA_PRIVATE, &private_value, sizeof(private_value) },
        { CKA_MODIFIABLE, &g_true, sizeof(g_true) },
        { CKA_LABEL, (void *)label, (CK_ULONG)strlen(label) },
        { CKA_VALUE, value, sizeof(value) - 1u },
    };

    return g_fn->C_CreateObject(g_session, attributes,
                                WT_ARRAY_SIZE(attributes), object);
}

static int test_object_create_size(void)
{
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_ULONG size = 0u;
    CK_RV rv;

    rv = create_data_object("size-object", CK_FALSE, &object);
    if (rv == CKR_OK) {
        rv = g_fn->C_GetObjectSize(g_session, object, &size);
    }
    if (object != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, object);
    }
    return rv == CKR_OK && size > 0u ? 0 : -1;
}

static int test_object_attributes(void)
{
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS object_class = 0u;
    CK_BYTE value[32];
    CK_ATTRIBUTE query = { CKA_VALUE, NULL, ~(CK_ULONG)0u };
    CK_ATTRIBUTE attributes[] = {
        { CKA_CLASS, &object_class, sizeof(object_class) },
        { CKA_VALUE, value, sizeof(value) },
    };
    CK_RV rv;

    rv = create_data_object("attribute-object", CK_FALSE, &object);
    if (rv == CKR_OK) {
        rv = g_fn->C_GetAttributeValue(g_session, object, &query, 1u);
    }
    if (rv == CKR_OK && (query.ulValueLen == 0u ||
            query.ulValueLen > sizeof(value))) {
        rv = CKR_FUNCTION_FAILED;
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_GetAttributeValue(g_session, object, attributes,
                                       WT_ARRAY_SIZE(attributes));
    }
    if (object != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, object);
    }
    if (rv != CKR_OK || object_class != CKO_DATA ||
            attributes[1].ulValueLen == 0u ||
            attributes[1].ulValueLen > sizeof(value)) {
        return -1;
    }
    return 0;
}

static int test_object_set_attribute(void)
{
    static const char new_label[] = "updated-object";
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_BYTE label[32];
    CK_ATTRIBUTE set = {
        CKA_LABEL, (void *)new_label, sizeof(new_label) - 1u
    };
    CK_ATTRIBUTE get = { CKA_LABEL, label, sizeof(label) };
    CK_RV rv;

    rv = create_data_object("old-object", CK_FALSE, &object);
    if (rv == CKR_OK) {
        rv = g_fn->C_SetAttributeValue(g_session, object, &set, 1u);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_GetAttributeValue(g_session, object, &get, 1u);
    }
    if (object != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, object);
    }
    if (rv != CKR_OK || get.ulValueLen != sizeof(new_label) - 1u ||
            memcmp(label, new_label, sizeof(new_label) - 1u) != 0) {
        return -1;
    }
    return 0;
}

static int test_object_copy(void)
{
    static const char copy_label[] = "copy-object";
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_ATTRIBUTE label = {
        CKA_LABEL, (void *)copy_label, sizeof(copy_label) - 1u
    };
    CK_RV rv;

    rv = create_data_object("source-object", CK_FALSE, &object);
    if (rv == CKR_OK) {
        rv = g_fn->C_CopyObject(g_session, object, &label, 1u, &copy);
    }
    if (copy != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, copy);
    }
    if (object != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, object);
    }
    return rv == CKR_OK && copy != CK_INVALID_HANDLE ? 0 : -1;
}

static int test_object_find(void)
{
    static const char label_text[] = "find-object";
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found[65];
    CK_ULONG count = 0u;
    CK_ATTRIBUTE label = {
        CKA_LABEL, (void *)label_text, sizeof(label_text) - 1u
    };
    CK_RV rv;

    rv = create_data_object(label_text, CK_FALSE, &object);
    if (rv == CKR_OK) {
        rv = g_fn->C_FindObjectsInit(g_session, &label, 1u);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_FindObjects(g_session, found, WT_ARRAY_SIZE(found),
                                 &count);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_FindObjectsFinal(g_session);
    }
    if (object != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, object);
    }
    return rv == CKR_OK && count == 1u && found[0] == object ? 0 : -1;
}

static int test_private_visibility(void)
{
    static const char label_text[] = "private-object";
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG count = 0u;
    CK_ATTRIBUTE label = {
        CKA_LABEL, (void *)label_text, sizeof(label_text) - 1u
    };
    CK_RV rv;

    rv = create_data_object(label_text, CK_TRUE, &object);
    if (rv == CKR_OK) {
        rv = g_fn->C_Logout(g_session);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_FindObjectsInit(g_session, &label, 1u);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_FindObjects(g_session, &found, 1u, &count);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_FindObjectsFinal(g_session);
    }
    if (g_fn->C_Login(g_session, CKU_USER, g_user_pin,
                      (CK_ULONG)(sizeof(g_user_pin) - 1u)) != CKR_OK) {
        rv = CKR_FUNCTION_FAILED;
    }
    if (object != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, object);
    }
    return rv == CKR_OK && count == 0u ? 0 : -1;
}

static int test_object_destroy(void)
{
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS object_class = 0u;
    CK_ATTRIBUTE attribute = {
        CKA_CLASS, &object_class, sizeof(object_class)
    };
    CK_RV rv;

    rv = create_data_object("destroy-object", CK_FALSE, &object);
    if (rv == CKR_OK) {
        rv = g_fn->C_DestroyObject(g_session, object);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_GetAttributeValue(g_session, object, &attribute, 1u);
    }
    return rv == CKR_OBJECT_HANDLE_INVALID ? 0 : -1;
}

static void run_object_suite(void)
{
    report_case("suite setup", suite_ready() == 0);
    if (g_session == CK_INVALID_HANDLE) {
        return;
    }
    run_case("object create and size", test_object_create_size);
    run_case("object attributes", test_object_attributes);
    run_case("object attribute update", test_object_set_attribute);
    run_case("object copy", test_object_copy);
    run_case("object find", test_object_find);
    run_case("private object visibility", test_private_visibility);
    run_case("object destroy", test_object_destroy);
    if (g_keep_session == 0) {
        suite_cleanup();
    }
}

static CK_RV generate_aes_key(CK_OBJECT_HANDLE *key)
{
    CK_ULONG value_len = 16u;
    CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL, 0u };
    CK_ATTRIBUTE attributes[] = {
        { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
        { CKA_KEY_TYPE, &g_aes_type, sizeof(g_aes_type) },
        { CKA_VALUE_LEN, &value_len, sizeof(value_len) },
        { CKA_TOKEN, &g_false, sizeof(g_false) },
        { CKA_ENCRYPT, &g_true, sizeof(g_true) },
        { CKA_DECRYPT, &g_true, sizeof(g_true) },
    };

    return g_fn->C_GenerateKey(g_session, &mechanism, attributes,
                               WT_ARRAY_SIZE(attributes), key);
}

static int aes_round_trip(CK_MECHANISM_TYPE type, void *parameter,
                          CK_ULONG parameter_len)
{
    static const CK_BYTE plain[16] = {
        0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
        0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42, 0x43
    };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mechanism = { type, parameter, parameter_len };
    CK_BYTE encrypted[64];
    CK_BYTE decrypted[32];
    CK_ULONG encrypted_len = sizeof(encrypted);
    CK_ULONG decrypted_len = sizeof(decrypted);
    CK_RV rv;
    unsigned int step = 1u;

    rv = generate_aes_key(&key);
    if (rv == CKR_OK) {
        step = 2u;
        rv = g_fn->C_EncryptInit(g_session, &mechanism, key);
    }
    if (rv == CKR_OK) {
        step = 3u;
        rv = g_fn->C_Encrypt(g_session, (CK_BYTE_PTR)plain, sizeof(plain),
                             encrypted, &encrypted_len);
    }
    if (rv == CKR_OK) {
        step = 4u;
        rv = g_fn->C_DecryptInit(g_session, &mechanism, key);
    }
    if (rv == CKR_OK) {
        step = 5u;
        rv = g_fn->C_Decrypt(g_session, encrypted, encrypted_len,
                             decrypted, &decrypted_len);
    }
    if (key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, key);
    }
    if (rv != CKR_OK || decrypted_len != sizeof(plain) ||
            memcmp(decrypted, plain, sizeof(plain)) != 0) {
        app_prefix();
        wt_pkcs11_puts("AES detail mechanism=");
        wt_pkcs11_print_u32((unsigned int)type);
        wt_pkcs11_puts(" step=");
        wt_pkcs11_print_u32(step);
        wt_pkcs11_puts(" rv=");
        wt_pkcs11_print_u32((unsigned int)rv);
        wt_pkcs11_puts(" encrypted=");
        wt_pkcs11_print_u32((unsigned int)encrypted_len);
        wt_pkcs11_puts(" decrypted=");
        wt_pkcs11_print_u32((unsigned int)decrypted_len);
        wt_pkcs11_puts("\r\n");
        return -1;
    }
    return 0;
}

static int test_random(void)
{
    CK_BYTE random[32];

    memset(random, 0, sizeof(random));
    if (g_fn->C_GenerateRandom(g_session, random, sizeof(random)) != CKR_OK) {
        return -1;
    }
    return buffer_nonzero(random, sizeof(random)) != 0 ? 0 : -1;
}

static int test_sha256(void)
{
    CK_MECHANISM mechanism = { CKM_SHA256, NULL, 0u };
    CK_BYTE digest[32];
    CK_ULONG digest_len = ~(CK_ULONG)0u;
    CK_RV rv;

    rv = g_fn->C_DigestInit(g_session, &mechanism);
    if (rv == CKR_OK) {
        rv = g_fn->C_Digest(g_session, (CK_BYTE_PTR)g_digest_input,
                            sizeof(g_digest_input) - 1u, NULL, &digest_len);
    }
    if (rv != CKR_OK || digest_len != sizeof(digest)) {
        return -1;
    }
    digest_len = sizeof(digest);
    if (rv == CKR_OK) {
        rv = g_fn->C_Digest(g_session, (CK_BYTE_PTR)g_digest_input,
                            sizeof(g_digest_input) - 1u, digest, &digest_len);
    }
    if (rv != CKR_OK || digest_len != sizeof(digest) ||
            memcmp(digest, g_sha256_abc, sizeof(digest)) != 0) {
        return -1;
    }
    digest_len = sizeof(digest);
    rv = g_fn->C_DigestInit(g_session, &mechanism);
    if (rv == CKR_OK) {
        rv = g_fn->C_DigestUpdate(g_session, (CK_BYTE_PTR)g_digest_input, 1u);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_DigestUpdate(g_session,
                                  (CK_BYTE_PTR)&g_digest_input[1], 2u);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_DigestFinal(g_session, digest, &digest_len);
    }
    return rv == CKR_OK && digest_len == sizeof(digest) &&
           memcmp(digest, g_sha256_abc, sizeof(digest)) == 0 ? 0 : -1;
}

static int test_hmac_sha256(void)
{
    static CK_BYTE key_value[] = "wolfTrust-hmac-key";
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mechanism = { CKM_SHA256_HMAC, NULL, 0u };
    CK_ATTRIBUTE attributes[] = {
        { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
        { CKA_KEY_TYPE, &g_generic_type, sizeof(g_generic_type) },
        { CKA_VALUE, key_value, sizeof(key_value) - 1u },
        { CKA_TOKEN, &g_false, sizeof(g_false) },
        { CKA_SIGN, &g_true, sizeof(g_true) },
        { CKA_VERIFY, &g_true, sizeof(g_true) },
    };
    CK_BYTE signature[32];
    CK_ULONG signature_len = sizeof(signature);
    CK_RV rv;

    rv = g_fn->C_CreateObject(g_session, attributes,
                              WT_ARRAY_SIZE(attributes), &key);
    if (rv == CKR_OK) {
        rv = g_fn->C_SignInit(g_session, &mechanism, key);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_Sign(g_session, (CK_BYTE_PTR)g_digest_input,
                          sizeof(g_digest_input) - 1u,
                          signature, &signature_len);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_VerifyInit(g_session, &mechanism, key);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_Verify(g_session, (CK_BYTE_PTR)g_digest_input,
                            sizeof(g_digest_input) - 1u,
                            signature, signature_len);
    }
    if (key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, key);
    }
    return rv == CKR_OK ? 0 : -1;
}

static int test_aes_cbc(void)
{
    CK_BYTE iv[16] = { 0u };

    return aes_round_trip(CKM_AES_CBC, iv, sizeof(iv));
}

static int test_aes_ctr(void)
{
    CK_AES_CTR_PARAMS parameters;

    memset(&parameters, 0, sizeof(parameters));
    parameters.ulCounterBits = 128u;
    return aes_round_trip(CKM_AES_CTR, &parameters, sizeof(parameters));
}

static int test_aes_gcm(void)
{
    CK_BYTE iv[12] = { 1u, 2u, 3u, 4u };
    CK_BYTE aad[8] = { 5u, 6u, 7u, 8u };
    CK_GCM_PARAMS parameters;

    memset(&parameters, 0, sizeof(parameters));
    parameters.pIv = iv;
    parameters.ulIvLen = sizeof(iv);
    parameters.ulIvBits = sizeof(iv) * 8u;
    parameters.pAAD = aad;
    parameters.ulAADLen = sizeof(aad);
    parameters.ulTagBits = 128u;
    return aes_round_trip(CKM_AES_GCM, &parameters, sizeof(parameters));
}

static int test_aes_ccm(void)
{
    CK_BYTE iv[12] = { 1u, 2u, 3u, 4u };
    CK_BYTE aad[8] = { 5u, 6u, 7u, 8u };
    CK_CCM_PARAMS parameters;

    memset(&parameters, 0, sizeof(parameters));
    parameters.ulDataLen = 16u;
    parameters.pIv = iv;
    parameters.ulIvLen = sizeof(iv);
    parameters.pAAD = aad;
    parameters.ulAADLen = sizeof(aad);
    parameters.ulMacLen = 16u;
    return aes_round_trip(CKM_AES_CCM, &parameters, sizeof(parameters));
}

static CK_RV generate_ec_key_pair(CK_BBOOL sign, CK_BBOOL derive,
                                  CK_OBJECT_HANDLE *public_key,
                                  CK_OBJECT_HANDLE *private_key)
{
    CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL, 0u };
    CK_ATTRIBUTE public_attributes[] = {
        { CKA_CLASS, &g_public_class, sizeof(g_public_class) },
        { CKA_KEY_TYPE, &g_ec_type, sizeof(g_ec_type) },
        { CKA_EC_PARAMS, (void *)g_p256_params, sizeof(g_p256_params) },
        { CKA_TOKEN, &g_false, sizeof(g_false) },
        { CKA_VERIFY, &sign, sizeof(sign) },
        { CKA_DERIVE, &derive, sizeof(derive) },
    };
    CK_ATTRIBUTE private_attributes[] = {
        { CKA_CLASS, &g_private_class, sizeof(g_private_class) },
        { CKA_KEY_TYPE, &g_ec_type, sizeof(g_ec_type) },
        { CKA_TOKEN, &g_false, sizeof(g_false) },
        { CKA_PRIVATE, &g_true, sizeof(g_true) },
        { CKA_SENSITIVE, &g_true, sizeof(g_true) },
        { CKA_SIGN, &sign, sizeof(sign) },
        { CKA_DERIVE, &derive, sizeof(derive) },
    };

    return g_fn->C_GenerateKeyPair(g_session, &mechanism,
                                   public_attributes,
                                   WT_ARRAY_SIZE(public_attributes),
                                   private_attributes,
                                   WT_ARRAY_SIZE(private_attributes),
                                   public_key, private_key);
}

static int test_hsm_ecdsa(void)
{
    static const CK_BYTE digest[32] = {
        0x50, 0x4b, 0x43, 0x53, 0x23, 0x31, 0x31, 0x20,
        0x6f, 0x76, 0x65, 0x72, 0x20, 0x66, 0x77, 0x54,
        0x50, 0x4d, 0x20, 0x74, 0x68, 0x72, 0x6f, 0x75,
        0x67, 0x68, 0x20, 0x53, 0x50, 0x4d, 0x20, 0x21
    };
    CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
    CK_MECHANISM mechanism = { CKM_ECDSA, NULL, 0u };
    CK_BYTE signature[64];
    CK_ULONG signature_len = sizeof(signature);
    CK_RV rv;

    rv = generate_ec_key_pair(CK_TRUE, CK_FALSE,
                              &public_key, &private_key);
    if (rv == CKR_OK) {
        rv = g_fn->C_SignInit(g_session, &mechanism, private_key);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_Sign(g_session, (CK_BYTE_PTR)digest, sizeof(digest),
                          signature, &signature_len);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_VerifyInit(g_session, &mechanism, public_key);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_Verify(g_session, (CK_BYTE_PTR)digest, sizeof(digest),
                            signature, signature_len);
    }
    if (private_key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, private_key);
    }
    if (public_key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, public_key);
    }
    return rv == CKR_OK ? 0 : -1;
}

static int test_hsm_ecdh(void)
{
    CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_BYTE point[80];
    CK_ATTRIBUTE point_attribute = { CKA_EC_POINT, point, sizeof(point) };
    CK_ULONG value_len = 32u;
    CK_ECDH1_DERIVE_PARAMS parameters;
    CK_MECHANISM mechanism;
    CK_ATTRIBUTE secret_attributes[] = {
        { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
        { CKA_KEY_TYPE, &g_generic_type, sizeof(g_generic_type) },
        { CKA_TOKEN, &g_false, sizeof(g_false) },
        { CKA_PRIVATE, &g_false, sizeof(g_false) },
        { CKA_SENSITIVE, &g_true, sizeof(g_true) },
        { CKA_EXTRACTABLE, &g_false, sizeof(g_false) },
        { CKA_VALUE_LEN, &value_len, sizeof(value_len) },
    };
    CK_RV rv;
    unsigned int step = 1u;

    rv = generate_ec_key_pair(CK_FALSE, CK_TRUE,
                              &public_key, &private_key);
    if (rv == CKR_OK) {
        step = 2u;
        rv = g_fn->C_GetAttributeValue(g_session, public_key,
                                       &point_attribute, 1u);
    }
    memset(&parameters, 0, sizeof(parameters));
    parameters.kdf = CKD_NULL;
    parameters.pPublicData = point;
    parameters.ulPublicDataLen = point_attribute.ulValueLen;
    mechanism.mechanism = CKM_ECDH1_DERIVE;
    mechanism.pParameter = &parameters;
    mechanism.ulParameterLen = sizeof(parameters);
    if (rv == CKR_OK) {
        step = 3u;
        rv = g_fn->C_DeriveKey(g_session, &mechanism, private_key,
                               secret_attributes,
                               WT_ARRAY_SIZE(secret_attributes), &secret);
    }
    if (rv == CKR_OK && secret == CK_INVALID_HANDLE) {
        step = 4u;
        rv = CKR_FUNCTION_FAILED;
    }
    if (secret != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, secret);
    }
    if (private_key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, private_key);
    }
    if (public_key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, public_key);
    }
    if (rv != CKR_OK) {
        app_prefix();
        wt_pkcs11_puts("ECDH detail step=");
        wt_pkcs11_print_u32(step);
        wt_pkcs11_puts(" rv=");
        wt_pkcs11_print_u32((unsigned int)rv);
        wt_pkcs11_puts(" point=");
        wt_pkcs11_print_u32((unsigned int)point_attribute.ulValueLen);
        wt_pkcs11_puts(" secret=");
        wt_pkcs11_print_u32((unsigned int)secret);
        wt_pkcs11_puts("\r\n");
    }
    return rv == CKR_OK ? 0 : -1;
}

static void run_crypto_suite(void)
{
    report_case("suite setup", suite_ready() == 0);
    if (g_session == CK_INVALID_HANDLE) {
        return;
    }
    run_case("random", test_random);
    run_case("SHA256 one-shot and multipart", test_sha256);
    run_case("HMAC SHA256", test_hmac_sha256);
    run_case("AES CBC", test_aes_cbc);
    run_case("AES CTR", test_aes_ctr);
    run_case("AES GCM", test_aes_gcm);
    run_case("AES CCM", test_aes_ccm);
    run_case("HSM-backed ECDSA", test_hsm_ecdsa);
    run_case("HSM-backed ECDH", test_hsm_ecdh);
    if (g_keep_session == 0) {
        suite_cleanup();
    }
}

static CK_RV test_create_mutex(CK_VOID_PTR_PTR mutex)
{
    *mutex = NULL;
    return CKR_OK;
}

static CK_RV test_mutex_op(CK_VOID_PTR mutex)
{
    (void)mutex;
    return CKR_OK;
}

static int test_bad_initialize_argument(void)
{
    CK_C_INITIALIZE_ARGS arguments;

    memset(&arguments, 0, sizeof(arguments));
    arguments.pReserved = &arguments;
    if (g_fn->C_Initialize(&arguments) != CKR_ARGUMENTS_BAD) {
        return -1;
    }
    memset(&arguments, 0, sizeof(arguments));
    arguments.CreateMutex = test_create_mutex;
    if (g_fn->C_Initialize(&arguments) != CKR_ARGUMENTS_BAD) {
        return -1;
    }
    arguments.DestroyMutex = test_mutex_op;
    arguments.LockMutex = test_mutex_op;
    arguments.UnlockMutex = test_mutex_op;
    if (g_fn->C_Initialize(&arguments) != CKR_CANT_LOCK) {
        return -1;
    }
    memset(&arguments, 0, sizeof(arguments));
    arguments.flags = CKF_OS_LOCKING_OK;
    return g_fn->C_Initialize(&arguments) == CKR_CANT_LOCK ? 0 : -1;
}

static int test_invalid_slot(void)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    return g_fn->C_OpenSession(0xffffu, CKF_SERIAL_SESSION, NULL, NULL,
                               &session) == CKR_SLOT_ID_INVALID ? 0 : -1;
}

static int test_invalid_session(void)
{
    CK_SESSION_INFO info;

    return g_fn->C_GetSessionInfo(CK_INVALID_HANDLE, &info) ==
           CKR_SESSION_HANDLE_INVALID ? 0 : -1;
}

static int test_wrong_pin(void)
{
    static CK_UTF8CHAR wrong_pin[] = "wrong-pin";
    CK_RV rv;

    rv = g_fn->C_Logout(g_session);
    if (rv == CKR_OK) {
        rv = g_fn->C_Login(g_session, CKU_USER, wrong_pin,
                           (CK_ULONG)(sizeof(wrong_pin) - 1u));
    }
    if (g_fn->C_Login(g_session, CKU_USER, g_user_pin,
                      (CK_ULONG)(sizeof(g_user_pin) - 1u)) != CKR_OK) {
        return -1;
    }
    return rv == CKR_PIN_INCORRECT ? 0 : -1;
}

static int test_invalid_object(void)
{
    CK_OBJECT_CLASS object_class = 0u;
    CK_ATTRIBUTE attribute = {
        CKA_CLASS, &object_class, sizeof(object_class)
    };

    return g_fn->C_GetAttributeValue(g_session, CK_INVALID_HANDLE,
                                     &attribute, 1u) ==
           CKR_OBJECT_HANDLE_INVALID ? 0 : -1;
}

static int test_null_create_template(void)
{
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;

    return g_fn->C_CreateObject(g_session, NULL, 1u, &object) ==
           CKR_ARGUMENTS_BAD ? 0 : -1;
}

static int test_unknown_mechanism(void)
{
    CK_MECHANISM mechanism = { 0x8000ffffUL, NULL, 0u };

    return g_fn->C_DigestInit(g_session, &mechanism) ==
           CKR_MECHANISM_INVALID ? 0 : -1;
}

static int test_short_digest_buffer(void)
{
    CK_MECHANISM mechanism = { CKM_SHA256, NULL, 0u };
    CK_BYTE digest[32];
    CK_ULONG digest_len = 1u;
    CK_RV rv;

    rv = g_fn->C_DigestInit(g_session, &mechanism);
    if (rv == CKR_OK) {
        rv = g_fn->C_Digest(g_session, (CK_BYTE_PTR)g_digest_input,
                            sizeof(g_digest_input) - 1u,
                            digest, &digest_len);
    }
    if (rv != CKR_BUFFER_TOO_SMALL) {
        return -1;
    }
    digest_len = sizeof(digest);
    return g_fn->C_Digest(g_session, (CK_BYTE_PTR)g_digest_input,
                          sizeof(g_digest_input) - 1u,
                          digest, &digest_len) == CKR_OK ? 0 : -1;
}

static int test_sign_without_init(void)
{
    CK_BYTE signature[64];
    CK_ULONG signature_len = sizeof(signature);

    return g_fn->C_Sign(g_session, (CK_BYTE_PTR)g_digest_input,
                        sizeof(g_digest_input) - 1u,
                        signature, &signature_len) ==
           CKR_OPERATION_NOT_INITIALIZED ? 0 : -1;
}

static int test_bad_signature(void)
{
    CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
    CK_MECHANISM mechanism = { CKM_ECDSA, NULL, 0u };
    CK_BYTE digest[32] = { 0x5au };
    CK_BYTE signature[64];
    CK_ULONG signature_len = sizeof(signature);
    CK_RV rv;

    rv = generate_ec_key_pair(CK_TRUE, CK_FALSE,
                              &public_key, &private_key);
    if (rv == CKR_OK) {
        rv = g_fn->C_SignInit(g_session, &mechanism, private_key);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_Sign(g_session, digest, sizeof(digest),
                          signature, &signature_len);
    }
    if (rv == CKR_OK) {
        signature[0] ^= 1u;
        rv = g_fn->C_VerifyInit(g_session, &mechanism, public_key);
    }
    if (rv == CKR_OK) {
        rv = g_fn->C_Verify(g_session, digest, sizeof(digest),
                            signature, signature_len);
    }
    if (private_key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, private_key);
    }
    if (public_key != CK_INVALID_HANDLE) {
        (void)g_fn->C_DestroyObject(g_session, public_key);
    }
    return rv == CKR_SIGNATURE_INVALID ? 0 : -1;
}

static void run_negative_suite(void)
{
    report_case("suite setup", suite_ready() == 0);
    if (g_session == CK_INVALID_HANDLE) {
        return;
    }
    run_case("reserved initialize argument rejected",
             test_bad_initialize_argument);
    run_case("invalid slot rejected", test_invalid_slot);
    run_case("invalid session rejected", test_invalid_session);
    run_case("wrong PIN rejected", test_wrong_pin);
    run_case("invalid object rejected", test_invalid_object);
    run_case("NULL create template rejected", test_null_create_template);
    run_case("unknown mechanism rejected", test_unknown_mechanism);
    run_case("short digest buffer reported", test_short_digest_buffer);
    run_case("sign without init rejected", test_sign_without_init);
    run_case("bad signature rejected", test_bad_signature);
    if (g_keep_session == 0) {
        suite_cleanup();
    }
}

const char *wt_pkcs11_suite_name(void)
{
#if defined(WT_PKCS11_SUITE_CORE)
    return "core";
#elif defined(WT_PKCS11_SUITE_OBJECTS)
    return "objects";
#elif defined(WT_PKCS11_SUITE_CRYPTO)
    return "crypto";
#elif defined(WT_PKCS11_SUITE_NEGATIVE)
    return "negative";
#else
    return "all";
#endif
}

int wt_pkcs11_run(void)
{
    g_passed = 0u;
    g_failed = 0u;

#if defined(WT_PKCS11_SUITE_ALL)
    g_keep_session = 1;
#endif
#if defined(WT_PKCS11_SUITE_CORE) || defined(WT_PKCS11_SUITE_ALL)
    run_core_suite();
#endif
#if defined(WT_PKCS11_SUITE_OBJECTS) || defined(WT_PKCS11_SUITE_ALL)
    run_object_suite();
#endif
#if defined(WT_PKCS11_SUITE_CRYPTO) || defined(WT_PKCS11_SUITE_ALL)
    run_crypto_suite();
#endif
#if defined(WT_PKCS11_SUITE_NEGATIVE) || defined(WT_PKCS11_SUITE_ALL)
    run_negative_suite();
#endif
#if defined(WT_PKCS11_SUITE_ALL)
    g_keep_session = 0;
    suite_cleanup();
#endif

    app_prefix();
    wt_pkcs11_puts("TOTAL PASSED: ");
    wt_pkcs11_print_u32(g_passed);
    wt_pkcs11_puts("\r\n");
    app_prefix();
    wt_pkcs11_puts("TOTAL FAILED: ");
    wt_pkcs11_print_u32(g_failed);
    wt_pkcs11_puts("\r\n");
    return g_failed == 0u ? 0 : -1;
}
