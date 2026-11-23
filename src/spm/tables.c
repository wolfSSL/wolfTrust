/* tables.c
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

#include "wolftrust/spm_tables.h"

static int wt_tables_sid_index(const wt_system_manifest_t* manifest,
                               uint32_t sid, size_t* owner)
{
    size_t p;
    size_t s;
    int index = 0;

    for (p = 0U; p < manifest->partition_count; p++) {
        for (s = 0U; s < manifest->partitions[p].service_count; s++) {
            if (manifest->partitions[p].services[s].sid == sid) {
                *owner = p;
                return index;
            }
            index++;
        }
    }
    return -1;
}

static int wt_tables_partition(const wt_system_manifest_t* manifest,
                               size_t p, wt_spm_tables_t* out)
{
    const wt_partition_manifest_t* partition = &manifest->partitions[p];
    wt_spm_sp_ipc_t* row = &out->sps[p];
    size_t i;

    if (partition->model != WT_PARTITION_MODEL_IPC ||
            partition->framework_version > (uint32_t)PSA_FRAMEWORK_VERSION ||
            partition->service_count >
                WT_SPM_MAX_SERVICES - out->service_count ||
            partition->interrupt_count > out->irq_cap - out->irq_count) {
        return WT_SPM_E_ARGUMENT;
    }
    if (partition->framework_version == WT_FFM_VERSION_1_1) {
        out->framework_version = WT_FFM_VERSION_1_1;
    }
    row->pid = (int32_t)partition->domain_id;
    row->signals = PSA_DOORBELL;
    for (i = 0U; i < partition->service_count; i++) {
        out->services[out->service_count].sid = partition->services[i].sid;
        out->services[out->service_count].version =
            partition->services[i].version;
        out->services[out->service_count].signal =
            partition->services[i].signal;
        out->services[out->service_count].sp = (uint8_t)p;
        out->services[out->service_count].policy =
            (uint8_t)partition->services[i].version_policy;
        out->services[out->service_count].ns_ok =
            partition->services[i].nonsecure_clients != 0U ? 1U : 0U;
        out->services[out->service_count].conn =
            partition->services[i].connection_based != 0U ? 1U : 0U;
        out->service_count++;
        row->signals |= partition->services[i].signal;
    }
    for (i = 0U; i < partition->interrupt_count; i++) {
        out->irqs[out->irq_count].irq = partition->interrupts[i].interrupt;
        out->irqs[out->irq_count].signal = partition->interrupts[i].signal;
        out->irqs[out->irq_count].sp = (uint8_t)p;
        out->irq_count++;
        row->signals |= partition->interrupts[i].signal;
    }
    return WT_SPM_OK;
}

int wt_spm_tables_derive(const wt_system_manifest_t* manifest,
                         wt_spm_tables_t* out)
{
    const wt_partition_manifest_t* partition;
    size_t owner = 0U;
    size_t p;
    size_t d;
    int index;
    int ret = WT_SPM_OK;

    if (manifest == NULL || out == NULL ||
            manifest->partition_count > WT_SPM_MAX_SPS) {
        return WT_SPM_E_ARGUMENT;
    }
    out->service_count = 0U;
    out->irq_count = 0U;
    out->sp_count = (uint8_t)manifest->partition_count;
    out->framework_version = WT_FFM_VERSION_1_0;
    if ((manifest->features & (WT_MANIFEST_FEATURE_SFN |
            WT_MANIFEST_FEATURE_STATELESS |
            WT_MANIFEST_FEATURE_MM_IOVEC)) != 0U) {
        out->framework_version = WT_FFM_VERSION_1_1;
    }
    for (p = 0U; p < manifest->partition_count && ret == WT_SPM_OK; p++) {
        ret = wt_tables_partition(manifest, p, out);
    }
    /* Dependencies resolve once every service has its row index. */
    for (p = 0U; p < manifest->partition_count && ret == WT_SPM_OK; p++) {
        partition = &manifest->partitions[p];
        out->sps[p].deps = 0U;
        for (d = 0U; d < partition->dependency_count; d++) {
            index = wt_tables_sid_index(manifest, partition->dependencies[d],
                                        &owner);
            /* A partition never calls its own services. */
            if (index >= 0 && owner != p) {
                out->sps[p].deps |= 1UL << (uint32_t)index;
            }
        }
    }
    if (out->framework_version > (uint32_t)PSA_FRAMEWORK_VERSION) {
        out->framework_version = (uint32_t)PSA_FRAMEWORK_VERSION;
    }
    return ret;
}
