#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_GLOBAL_EXCEPTION_INFO_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_GLOBAL_EXCEPTION_INFO_H

#include "CommonTypes.h"
#include "ExceptionAnalysisInfo.h"
#include "TUDependencyGraph.h"

#include "clang/AST/Decl.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"

#include <mutex>
#include <string>
#include <vector>

namespace clang {
namespace exception_scan {

/// Information about a function definition or declaration
struct FunctionMappingInfo {
  USRTy USR;
  PathTy TU;
  OwningStringTy FunctionName;
  PathTy SourceLocFile;
  unsigned SourceLocLine;
  unsigned SourceLocColumn;
  bool IsDefinition;
};

/// Information about a function call
struct CallDependency {
  USRTy CallerUSR;        ///< USR of the calling function
  USRTy CalleeUSR;        ///< USR of the called function
  PathTy CallLocFile;     ///< File containing the call
  unsigned CallLocLine;   ///< Line number of the call
  unsigned CallLocColumn; ///< Column number of the call

  bool operator==(const CallDependency &other) const {
    return CallerUSR == other.CallerUSR && CalleeUSR == other.CalleeUSR &&
           CallLocFile == other.CallLocFile &&
           CallLocLine == other.CallLocLine &&
           CallLocColumn == other.CallLocColumn;
  }
};

} // namespace exception_scan
} // namespace clang

// implement DenseMapInfo for CallDependency
namespace llvm {
template <> struct DenseMapInfo<clang::exception_scan::CallDependency> {
  static inline clang::exception_scan::CallDependency getEmptyKey() {
    return clang::exception_scan::CallDependency{};
  }
  static inline clang::exception_scan::CallDependency getTombstoneKey() {
    return clang::exception_scan::CallDependency{
        clang::exception_scan::USRTy(),
        clang::exception_scan::USRTy(),
        clang::exception_scan::PathTy(),
        UINT_MAX,
        UINT_MAX,
    };
  }
  static unsigned
  getHashValue(const clang::exception_scan::CallDependency &Val) {
    return llvm::hash_combine(Val.CallerUSR, Val.CalleeUSR, Val.CallLocFile,
                              Val.CallLocLine, Val.CallLocColumn);
  }
  static bool isEqual(const clang::exception_scan::CallDependency &LHS,
                      const clang::exception_scan::CallDependency &RHS) {
    return LHS == RHS;
  }
};
} // namespace llvm

namespace clang {
namespace exception_scan {

/// Information about a function that appears in a noexcept clause
struct NoexceptDependeeInfo {
  USRTy USR;                   ///< USR of the function
  PathTy TU;                   ///< Translation unit containing the function
  OwningStringTy FunctionName; ///< Name of the function
  PathTy SourceLocFile;        ///< File containing the function
  unsigned SourceLocLine;      ///< Line number of the function
  unsigned SourceLocColumn;    ///< Column number of the function
  PathTy NoexceptLocFile;      ///< File containing the noexcept clause
  unsigned NoexceptLocLine;    ///< Line number of the noexcept clause
  unsigned NoexceptLocColumn;  ///< Column number of the noexcept clause
};

/// Global call graph data structure
struct GlobalExceptionInfo {
  llvm::DenseSet<CallDependency>
      CallDependencies;                     ///< Function call dependencies
  mutable std::mutex CallDependenciesMutex; ///< Mutex for call dependencies

  llvm::StringMap<FunctionMappingInfo>
      USRToFunctionMap;                     ///< Map from USR to function info
  mutable std::mutex USRToFunctionMapMutex; ///< Mutex for USR map

  llvm::StringMap<GlobalFunctionExceptionInfo>
      USRToExceptionMap;                     ///< Map from USR to exception info
  mutable std::mutex USRToExceptionMapMutex; ///< Mutex for exception map

  // Data structures for cross-TU analysis
  llvm::StringSet<> TUs;       ///< Set of all TUs
  mutable std::mutex TUsMutex; ///< Mutex for TUs

  TUDependencyGraph TUDependencies; ///< Translation unit dependencies
  // TUDependencyGraph handles synchronized access to its internal data,
  // that is why we don't need a mutex here.

  // TODO: Handle functions defined in multiple TUs and use build
  // information to determine which TU should be considered when looking
  // for the definition of a function. A function can be defined in
  // multiple TUs without violating the one definition rule. These TUs are
  // not necessarily used together.
  llvm::StringMap<llvm::StringSet<>>
      USRToDefinedInTUMap;                     ///< Map from USR to list of TUs
  mutable std::mutex USRToDefinedInTUMapMutex; ///< Mutex for USR to TU map

  llvm::StringMap<llvm::StringSet<>>
      TUToUSRMap;                     ///< Map from TU to list of USRs
  mutable std::mutex TUToUSRMapMutex; ///< Mutex for TU to USR map

  // NoexceptDependeeInfo is too big for SmallVector, the instantiation
  // of the SmallVector template asserts that sizeof(T) <= 256. We could force
  // by providing the number or explicit elements.
  std::vector<NoexceptDependeeInfo>
      NoexceptDependees; ///< Functions that appear in noexcept clauses
  mutable std::mutex NoexceptDependeesMutex; ///< Mutex for noexcept dependees
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_GLOBAL_EXCEPTION_INFO_H