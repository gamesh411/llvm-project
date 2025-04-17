#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_GLOBAL_EXCEPTION_INFO_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_GLOBAL_EXCEPTION_INFO_H

#include "clang/AST/Decl.h"
#include "clang/Basic/SourceLocation.h"

#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace clang {
namespace exception_scan {

/// Information about a function definition or declaration
struct FunctionMappingInfo {
  std::string USR;
  std::string TU;
  std::string FunctionName;
  clang::SourceLocation Loc;
  bool IsDefinition;
};

/// Information about a function call
struct CallDependency {
  std::string CallerUSR;   ///< USR of the calling function
  std::string CalleeUSR;   ///< USR of the called function
  std::string CallLocFile; ///< File containing the call
  unsigned CallLocLine;    ///< Line number of the call
  unsigned CallLocColumn;  ///< Column number of the call
};

/// Information about a function that appears in a noexcept clause
struct NoexceptDependeeInfo {
  std::string USR;             ///< USR of the function
  std::string TU;              ///< Translation unit containing the function
  std::string FunctionName;    ///< Name of the function
  clang::SourceLocation Loc;   ///< Location of the function
  std::string NoexceptLocFile; ///< File containing the noexcept clause
  unsigned NoexceptLocLine;    ///< Line number of the noexcept clause
  unsigned NoexceptLocColumn;  ///< Column number of the noexcept clause
};

/// Represents a translation unit dependency
struct TUDependency {
  std::string SourceTU; ///< Source translation unit
  std::string TargetTU; ///< Target translation unit
};

/// Global call graph data structure
struct GlobalExceptionInfo {
  std::vector<CallDependency> CallDependencies; ///< Function call dependencies
  std::unordered_map<std::string, FunctionMappingInfo>
      USRToFunctionMap; ///< Map from USR to function info
  // Data structures for cross-TU analysis
  std::set<std::string> TUs;                ///< Set of all TUs
  std::vector<TUDependency> TUDependencies; ///< Translation unit dependencies

  // TODO: Handle functions defined in multiple TUs and use build
  // information to determine which TU should be considered when looking
  // for the definition of a function. A function can be defined in
  // multiple TUs without violating the one definition rule. These TUs are
  // not necessarily used together.
  std::unordered_map<std::string, std::string>
      USRToDefinedInTUMap; ///< Map from USR to list of TUs
  std::unordered_map<std::string, std::set<std::string>>
      TUToUSRMap;                      ///< Map from TU to list of USRs
  std::mutex CallDependenciesMutex;    ///< Mutex for call dependencies
  std::mutex USRToFunctionMapMutex;    ///< Mutex for USR map
  std::mutex TUsMutex;                 ///< Mutex for TUs
  std::mutex TUDependenciesMutex;      ///< Mutex for TU dependencies
  std::mutex USRToDefinedInTUMapMutex; ///< Mutex for USR to TU map
  std::mutex TUToUSRMapMutex;          ///< Mutex for TU to USR map

  // Data structures for noexcept-dependee functions
  std::vector<NoexceptDependeeInfo>
      NoexceptDependees; ///< Functions that appear in noexcept clauses
  std::mutex NoexceptDependeesMutex; ///< Mutex for noexcept dependees
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_GLOBAL_EXCEPTION_INFO_H