# Makefile
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

# The STM32L562 manifests must grant each guest exactly the flash and RAM
# windows memory_map.h gives it, in both the production and conformance layout.
ROOT := ../../..
CC ?= cc
PYTHON ?= python3

.PHONY: all run compilers sanitize valgrind clean

all run compilers sanitize valgrind:
	$(PYTHON) -I check_layout.py --cc "$(CC)" --root $(ROOT)

clean:
	@:
