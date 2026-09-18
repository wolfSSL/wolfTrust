/* libc_stubs.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335,
 * USA
 */

#ifndef WOLFTRUST_LIBC_STUBS_H
#define WOLFTRUST_LIBC_STUBS_H

#include <stddef.h>

void* memcpy(void* dst, const void* src, size_t size);
void* memset(void* dst, int value, size_t size);
void* memmove(void* dst, const void* src, size_t size);
int memcmp(const void* lhs, const void* rhs, size_t size);

size_t strlen(const char* str);
int strcmp(const char* lhs, const char* rhs);
int strncmp(const char* lhs, const char* rhs, size_t size);
char* strncpy(char* dst, const char* src, size_t size);
int strcasecmp(const char* lhs, const char* rhs);
int strncasecmp(const char* lhs, const char* rhs, size_t size);

int tolower(int value);
int toupper(int value);
int isspace(int value);
int isdigit(int value);
int isalpha(int value);
int isalnum(int value);
int isxdigit(int value);
int isupper(int value);
int islower(int value);
int iscntrl(int value);
int isprint(int value);

#endif /* WOLFTRUST_LIBC_STUBS_H */
