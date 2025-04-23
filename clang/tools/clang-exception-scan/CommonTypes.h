#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_COMMONTYPES_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_COMMONTYPES_H

#include "llvm/ADT/SmallString.h"

namespace clang {
namespace exception_scan {

using PathTy = llvm::SmallString<128>;
using USRTy = llvm::SmallString<64>;
using OwningStringTy = llvm::SmallString<64>;

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_COMMONTYPES_H
