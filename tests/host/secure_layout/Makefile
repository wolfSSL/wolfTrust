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

.PHONY: all run clean sanitize valgrind

all: run

run:
	@python3 ../../../tools/check_secure_layout.py --self-test
	@out="$$( $(MAKE) --no-print-directory -C ../../.. \
		WT_LTO=invalid -n secure-image 2>&1 )"; status=$$?; \
	if [ $$status -eq 0 ]; then \
		echo "FAIL: invalid WT_LTO value was accepted" >&2; \
		exit 1; \
	fi; \
	printf '%s\n' "$$out" | \
		grep -Fq "unsupported WT_LTO='invalid'"

sanitize: run

valgrind: run

clean:
	@:
