#!/bin/sh
# Compile the host and every Armv8-M port under a static-analysis build tracer.
set -eu

make test

for target in stm32h563 mimxrt700 mcxn947; do
    for engine in native hsm; do
        case "$target" in
            mimxrt700|mcxn947) attest_cose=0 ;;
            *) attest_cose=1 ;;
        esac
        make TARGET="$target" WT_ENGINE="$engine" \
            WT_ATTEST_COSE="$attest_cose" \
            BUILD_DIR="build/static-analysis-$target-$engine" \
            TOOLPREFIX=arm-none-eabi- secure-image
    done
done
