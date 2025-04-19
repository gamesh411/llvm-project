#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYZER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYZER_H

#include "ExceptionAnalysisInfo.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtCXX.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringRef.h"
#include <string>
#include <vector>

namespace clang {
namespace exception_scan {

/// Exception analyzer that focuses on function calls and exception
/// specifications
class ExceptionAnalyzer {
public:
  explicit ExceptionAnalyzer(ASTContext &Context);

  /// Analyze a function and determine its exception behavior
  FunctionExceptionInfo analyzeFunction(const FunctionDecl *Func);

  /// Configure the analyzer to ignore std::bad_alloc exceptions
  void ignoreBadAlloc(bool Value) { IgnoreBadAlloc_ = Value; }

  /// Configure the analyzer to ignore specific exception types
  void ignoreExceptions(const std::vector<std::string> &Types) {
    IgnoredExceptions_ = Types;
  }

  /// Check if a function is a builtin that doesn't throw
  bool isNoexceptBuiltin(const FunctionDecl *FD) const;

private:
  /// Analyze a statement and update the exception information
  void analyzeStatement(const Stmt *S, FunctionExceptionInfo &Info);

  /// Analyze a function call
  void analyzeCallExpr(const CallExpr *Call, FunctionExceptionInfo &Info);

  /// Analyze a throw expression
  void analyzeThrowExpr(const CXXThrowExpr *Throw, FunctionExceptionInfo &Info);

  /// Get condition information from an expression
  ExceptionCondition getConditionInfo(const Expr *Cond) const;

  /// Get the parent statement of a given statement
  const Stmt *getParentStmt(const Stmt *S) const;

  /// Build a map of statements to their parents
  void buildParentMap(const Stmt *S);

  ASTContext &Context_;         ///< AST context
  bool IgnoreBadAlloc_ = false; ///< Whether to ignore std::bad_alloc
  std::vector<std::string> IgnoredExceptions_; ///< Exception types to ignore
  llvm::DenseMap<const FunctionDecl *, FunctionExceptionInfo> FunctionCache_;
  llvm::DenseMap<const Stmt *, const Stmt *>
      ParentMap_; ///< Maps statements to their parents
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYZER_H