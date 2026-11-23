# The SPM core and its host fixture, for suites that serve calls inline.
# Include after CFLAGS and BUILD_DIR are set; link $(SPM_HOST_OBJS).
SPM_HOST_DIR := $(ROOT)/tests/host/support
SPM_HOST_SRCS := $(ROOT)/src/spm/core.c $(ROOT)/src/spm/tables.c \
    $(SPM_HOST_DIR)/spm_host.c
SPM_HOST_OBJS = $(addprefix $(BUILD_DIR)/spmhost_,\
    $(notdir $(SPM_HOST_SRCS:.c=.o)))
CFLAGS += -I$(SPM_HOST_DIR) -DWT_SPM_TABLE= -DWT_SP_RESTART=1 \
    -DWT_GUEST_RESTART=1

$(BUILD_DIR)/spmhost_%.o: $(ROOT)/src/spm/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/spmhost_%.o: $(SPM_HOST_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
