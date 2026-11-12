# The layout configuration of port $(TARGET) for a host fixture: the same
# defines and include paths the secure firmware is compiled with, from the
# same fragments. The fixture sets ROOT and TARGET, then includes this.
ARCH ?= armv8m
WT_LAYOUT_CPP ?= $(CC)
include $(ROOT)/mk/target-$(TARGET).mk
include $(ROOT)/mk/layout.mk
# The renderer runs on every make and writes only on change, as the
# firmware's does, so a fixture follows every layout input and header.
WT_MANIFEST_RENDER_DEPS += FORCE
.PHONY: FORCE
FORCE:
