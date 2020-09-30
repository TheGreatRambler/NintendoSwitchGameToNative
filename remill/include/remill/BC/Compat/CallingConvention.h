/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <llvm/IR/CallingConv.h>

#include "remill/BC/Version.h"

namespace llvm {
namespace CallingConv {

#if LLVM_VERSION_NUMBER < LLVM_VERSION(5, 0)
constexpr auto Win64 = X86_64_Win64;
#endif

}  // namespace CallingConv
}  // namespace llvm
