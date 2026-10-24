#!/bin/sh

case "${WT_TPM_TEST_MODE:-tpm}" in
    tpm)
        echo "tpm-guest0: alive"
        echo "ftpm-guest1: ready"
        echo "tpm-guest0: tpm init ok"
        echo "tpm-guest0: tpm sign ok"
        echo "tpm-guest0: tpm round trip ok"
        ;;
    pkcs11)
        echo "pkcs11-freertos: alive"
        echo "pkcs11-freertos: scheduler started"
        echo "pkcs11-provider: ready"
        echo "pkcs11-freertos: TOTAL FAILED: 0"
        echo "pkcs11-freertos: suite ${WT_PKCS11_SUITE:-all} complete"
        ;;
    *)
        exit 2
        ;;
esac

exit 127
