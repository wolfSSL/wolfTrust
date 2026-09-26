/* main.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* WT-PORT-0008: the shared per-dispatch window helper closes the whole guest
 * RAM extent and reopens exactly the arriving guest's writable, in-extent
 * windows, in order, then commits. Fake primitives record the sequence so the
 * math is proven without a fabric (GTZC on H5, SAU on RT700). */

#include "wolftrust/fabric_windows.h"

#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

#define EXTENT_BASE 0x20100000u
#define EXTENT_END  0x20180000u

static int g_close_calls;
static int g_commit_calls;
static int g_open_calls;
static int g_close_before_open;
static int g_opens_at_commit;
static uintptr_t g_open_base[8];
static size_t g_open_size[8];

static void fake_close(void)
{
    g_close_calls++;
    if (g_open_calls == 0) {
        g_close_before_open = 1;
    }
}

static void fake_open(uintptr_t base, size_t size)
{
    if (g_open_calls < 8) {
        g_open_base[g_open_calls] = base;
        g_open_size[g_open_calls] = size;
    }
    g_open_calls++;
}

/* Snapshot the open count so a commit issued before the last open is caught. */
static void fake_commit(void)
{
    g_commit_calls++;
    g_opens_at_commit = g_open_calls;
}

static const wt_fabric_windows_t g_fabric = {
    EXTENT_BASE, EXTENT_END, fake_close, fake_open, fake_commit
};

static void reset_record(void)
{
    g_close_calls = 0;
    g_commit_calls = 0;
    g_open_calls = 0;
    g_close_before_open = 0;
    g_opens_at_commit = -1;
    memset(g_open_base, 0, sizeof(g_open_base));
    memset(g_open_size, 0, sizeof(g_open_size));
}

static wt_memory_window_t win(uintptr_t base, size_t size, uint32_t attr)
{
    wt_memory_window_t w;

    memset(&w, 0, sizeof(w));
    w.base = base;
    w.size = size;
    w.attributes = attr;
    return w;
}

int main(void)
{
    wt_memory_window_t windows[4];

    printf("RUN: unit/fabric_windows\n");

    /* One writable in-extent window reopens exactly itself, close first,
     * commit last. */
    reset_record();
    windows[0] = win(EXTENT_BASE, 0x40000u, WT_MEMORY_ATTR_WRITE);
    wt_fabric_apply_windows(&g_fabric, windows, 1);
    check(g_close_calls == 1, "close_all runs once");
    check(g_close_before_open == 1, "close_all runs before any open");
    check(g_open_calls == 1, "one writable window reopened");
    check(g_open_base[0] == EXTENT_BASE && g_open_size[0] == 0x40000u,
          "reopened window has the requested base and size");
    check(g_commit_calls == 1 && g_close_calls == 1 && g_opens_at_commit == 1,
          "commit runs once, after close_all and the last open");

    /* A read-only window is never reopened Non-secure. */
    reset_record();
    windows[0] = win(EXTENT_BASE, 0x40000u, WT_MEMORY_ATTR_READ);
    wt_fabric_apply_windows(&g_fabric, windows, 1);
    check(g_close_calls == 1 && g_open_calls == 0,
          "read-only window closed but not reopened");

    /* A window outside the extent (a peripheral) is skipped. */
    reset_record();
    windows[0] = win(0x40110000u, 0x1000u, WT_MEMORY_ATTR_WRITE);
    wt_fabric_apply_windows(&g_fabric, windows, 1);
    check(g_open_calls == 0, "out-of-extent window skipped");

    /* A window that starts below the extent base but ends inside the extent
     * is skipped by the lower-bound check alone. */
    reset_record();
    windows[0] = win(EXTENT_BASE - 0x10000u, 0x20000u, WT_MEMORY_ATTR_WRITE);
    wt_fabric_apply_windows(&g_fabric, windows, 1);
    check(g_open_calls == 0, "window starting below the extent base skipped");

    /* A window that starts in-extent but runs past the end is skipped whole. */
    reset_record();
    windows[0] = win(EXTENT_END - 0x10000u, 0x20000u, WT_MEMORY_ATTR_WRITE);
    wt_fabric_apply_windows(&g_fabric, windows, 1);
    check(g_open_calls == 0, "window crossing the extent end skipped");

    /* An empty window is skipped. */
    reset_record();
    windows[0] = win(EXTENT_BASE, 0u, WT_MEMORY_ATTR_WRITE);
    wt_fabric_apply_windows(&g_fabric, windows, 1);
    check(g_open_calls == 0, "empty window skipped");

    /* Mixed set: only the writable in-extent windows reopen, in order. */
    reset_record();
    windows[0] = win(EXTENT_BASE, 0x20000u, WT_MEMORY_ATTR_WRITE);
    windows[1] = win(0x40110000u, 0x1000u, WT_MEMORY_ATTR_WRITE);
    windows[2] = win(EXTENT_BASE + 0x20000u, 0x20000u,
                     WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE);
    windows[3] = win(EXTENT_BASE + 0x40000u, 0x10000u, WT_MEMORY_ATTR_READ);
    wt_fabric_apply_windows(&g_fabric, windows, 4);
    check(g_open_calls == 2, "two of four windows reopened");
    check(g_open_base[0] == EXTENT_BASE &&
          g_open_base[1] == EXTENT_BASE + 0x20000u,
          "reopened windows kept their manifest order");
    check(g_commit_calls == 1 && g_opens_at_commit == 2,
          "commit runs once after the second open");

    /* Zero windows still closes the extent (fully Secure) and commits. */
    reset_record();
    wt_fabric_apply_windows(&g_fabric, NULL, 0);
    check(g_close_calls == 1 && g_open_calls == 0 && g_commit_calls == 1,
          "no windows closes the whole extent");

    /* A NULL descriptor or missing primitive is a safe no-op. */
    reset_record();
    wt_fabric_apply_windows(NULL, windows, 1);
    check(g_close_calls == 0 && g_open_calls == 0 && g_commit_calls == 0,
          "NULL descriptor is a no-op");

    if (failures == 0) {
        printf("PASS: unit/fabric_windows (%d checks)\n", checks);
        return 0;
    }
    printf("FAIL: unit/fabric_windows (%d/%d failed)\n", failures, checks);
    return 1;
}
