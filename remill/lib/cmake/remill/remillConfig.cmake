# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.2)

if(NOT TARGET remill)
  if(WIN32)
    set(REMILL_LIBRARY_LOCATION "D:/remill/remill/lib/remill.lib")
    set(REMILL_INCLUDE_LOCATION "D:/remill/remill/include")
  else()
    set(REMILL_LIBRARY_LOCATION "D:/remill/lib/libremill.a")
    set(REMILL_INCLUDE_LOCATION "D:/remill/include")
  endif()

  add_library(remill STATIC IMPORTED)
  set_property(TARGET remill PROPERTY IMPORTED_LOCATION "D:/remill/remill/lib/libremill.a")
  target_include_directories(remill INTERFACE "D:/remill/remill/include")

  target_compile_definitions(remill INTERFACE "REMILL_INSTALL_SEMANTICS_DIR=\"D:/remill/remill/5.0/semantics/\"")
  target_compile_definitions(remill INTERFACE "REMILL_BUILD_SEMANTICS_DIR_X86=\"D:/remill/remill/5.0/semantics/\"")
  target_compile_definitions(remill INTERFACE "REMILL_BUILD_SEMANTICS_DIR_AARCH64=\"D:/remill/remill/5.0/semantics/\"")

  # Add a dummy 'semantics' target to satisfy the protobuf generator
  add_custom_target(semantics)
endif()
