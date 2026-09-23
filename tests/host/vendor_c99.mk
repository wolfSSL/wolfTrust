# Keep C99 diagnostics on wolfTrust code, not external dependency headers.
ifneq ($(findstring clang,$(shell $(CC) --version 2>/dev/null)),)
CFLAGS += --system-header-prefix=wolfssl/ \
    --system-header-prefix=wolfhsm/
else
CFLAGS += -isystem $(WOLFSSL) $(if $(WOLFHSM),-isystem $(WOLFHSM))
endif
