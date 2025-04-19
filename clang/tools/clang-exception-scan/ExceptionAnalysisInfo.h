#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYSISINFO_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYSISINFO_H

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceLocation.h"
#include <string>
#include <vector>

namespace clang {
namespace exception_scan {

/// Represents the state of a function regarding its exception behavior
enum class ExceptionState {
  NotThrowing = 0, ///< Function does not throw exceptions
  Throwing = 1,    ///< Function can throw exceptions
  Unknown = 2      ///< Function's exception behavior is unknown
};

/// Represents a condition under which an exception might be thrown
struct ExceptionCondition {
  std::string Condition; ///< String representation of the condition
  SourceLocation Loc;    ///< Source location of the condition
  std::string File;      ///< File containing the condition
  unsigned Line;         ///< Line number of the condition
  unsigned Column;       ///< Column number of the condition
};

/// Represents information about a specific exception type
struct ThrowInfo {
  const Stmt *ThrowStmt;
  QualType Type;        ///< The exception type
  std::string TypeName; ///< String representation of the type
  std::vector<ExceptionCondition>
      Conditions; ///< Conditions under which this type is thrown
};

/// Represents detailed exception information for a function
struct FunctionExceptionInfo {
  const FunctionDecl *Function; ///< The function declaration
  ExceptionState State;         ///< The function's exception state
  bool ContainsUnknown; ///< Whether the function contains unknown elements
  std::vector<ThrowInfo>
      ThrowEvents; ///< Types of exceptions that can be thrown
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYSISINFO_H