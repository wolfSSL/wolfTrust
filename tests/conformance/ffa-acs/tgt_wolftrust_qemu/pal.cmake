# pal.cmake
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# FF-A ACS platform layer for the wolfTrust QEMU targets. The interrupt and
# MMIO sources are the suite's own generic ones; only the machine-specific
# files live in this target.
set(PAL_SRC
    ${ROOT_DIR}/platform/common/src/pal_libc.c
    ${ROOT_DIR}/platform/common/src/pal_misc_asm.S
    ${ROOT_DIR}/platform/common/src/pal_spinlock.S
    ${ROOT_DIR}/platform/common/src/pal_sp_helpers.c
    ${ROOT_DIR}/platform/common/src/pal_spm_helpers.c
    ${ROOT_DIR}/platform/common/src/pal_asm_smc.S
    ${ROOT_DIR}/platform/pal_baremetal/${TARGET}/src/pal_console.c
    ${ROOT_DIR}/platform/pal_baremetal/${TARGET}/src/pal_driver.c
    ${ROOT_DIR}/platform/pal_baremetal/${TARGET}/src/pal_misc.c
    ${ROOT_DIR}/platform/pal_baremetal/${TARGET}/src/pal_vcpu_setup.c
    ${ROOT_DIR}/platform/pal_baremetal/tgt_tfa_fvp/src/pal_mmio.c
    ${ROOT_DIR}/platform/pal_baremetal/tgt_tfa_fvp/src/pal_irq.c
    ${ROOT_DIR}/platform/driver/src/pal_log.c
    ${ROOT_DIR}/platform/driver/src/pal_nvm.c
    ${ROOT_DIR}/platform/driver/src/gic/pal_arm_gic_v2v3.c
    ${ROOT_DIR}/platform/driver/src/gic/pal_gic_common.c
    ${ROOT_DIR}/platform/driver/src/gic/pal_arm_gic_v2.c
    ${ROOT_DIR}/platform/driver/src/gic/pal_gic_v3.c
    ${ROOT_DIR}/platform/driver/src/gic/pal_gic_v2.c
    ${ROOT_DIR}/platform/driver/src/gic/platform.S
)

add_library(${PAL_LIB} STATIC ${PAL_SRC})

target_include_directories(${PAL_LIB} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${ROOT_DIR}/platform/common/inc/
    ${ROOT_DIR}/platform/common/inc/aarch64/
    ${ROOT_DIR}/platform/pal_baremetal/${TARGET}/inc
    ${ROOT_DIR}/platform/driver/inc/
)

unset(PAL_SRC)
