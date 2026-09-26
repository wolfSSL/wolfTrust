/* sid.h
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

/* Service identifiers the storage client resolves outside conformance builds
 * (which use the generated psa_manifest/sid.h instead), from the platform
 * manifest (SERVICE_ITS and SERVICE_PS carry the same SIDs on every port). */

#ifndef PSA_MANIFEST_SID_H
#define PSA_MANIFEST_SID_H

#define SERVICE_ITS_SID 4099U
#define SERVICE_PS_SID  4100U

#endif /* PSA_MANIFEST_SID_H */
