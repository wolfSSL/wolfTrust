# wolfTrust host CI image.
#
# Bakes in the host toolchains every PR job used to apt-get at job time, so CI
# just pulls this image instead of installing packages on every run. Slim
# Debian base with no emulator; the Arm cross and m33mu jobs use the separate
# wolfboot-ci-m33mu image. Built and pushed to ghcr.io/wolfssl/wolftrust-ci:latest
# by publish-ci-image.yml.

FROM debian:sid-slim

ENV DEBIAN_FRONTEND=noninteractive

# One apt-get install. Anything added here ships in the image; do not add
# per-workflow installs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential gcc-12 gcc-13 gcc-14 gcc-15 \
        clang clang-19 clang-21 libclang-rt-21-dev \
        valgrind \
        autoconf automake libtool libtool-bin pkg-config m4 \
        make git ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
