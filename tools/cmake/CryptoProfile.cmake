# CryptoProfile.cmake
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

function(wt_crypto_profile root output)
  if(NOT DEFINED WT_CRYPTO_PROFILE)
    if(DEFINED ENV{WT_CRYPTO_PROFILE})
      set(WT_CRYPTO_PROFILE "$ENV{WT_CRYPTO_PROFILE}")
    else()
      set(WT_CRYPTO_PROFILE default)
    endif()
  endif()
  set(WT_CRYPTO_PROFILE "${WT_CRYPTO_PROFILE}" PARENT_SCOPE)
  get_filename_component(root "${root}" ABSOLUTE)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  execute_process(
    COMMAND ${Python3_EXECUTABLE} ${root}/tools/crypto_profile.py
            --root ${root} --output ${output} --profile ${WT_CRYPTO_PROFILE}
    RESULT_VARIABLE result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not generate the crypto operation profile")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${root}/tools/crypto_profile.py ${root}/config/crypto-profiles.json)
  if(DEFINED ENV{WT_CRYPTO_CONFIG})
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
      "$ENV{WT_CRYPTO_CONFIG}")
  endif()
endfunction()
