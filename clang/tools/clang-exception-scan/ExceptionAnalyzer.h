#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYZER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYZER_H

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringRef.h"
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
  llvm::SmallSet<const FunctionDecl *, 8>
      CallGraph; ///< Functions called by this function
};

/// Enhanced exception analyzer that includes call graph analysis and condition
/// tracking
class ExceptionAnalyzer {
public:
  explicit ExceptionAnalyzer(ASTContext &Context);
  FunctionExceptionInfo analyzeFunction(const FunctionDecl *Func);
  FunctionExceptionInfo analyzeStatement(const Stmt *S);
  llvm::SmallSet<const FunctionDecl *, 8>
  getCallGraph(const FunctionDecl *Func) const;
  std::vector<ExceptionCondition>
  getExceptionConditions(const FunctionDecl *Func) const;
  ExceptionCondition getConditionInfo(const Expr *Cond) const;
  void buildCallGraph(const FunctionDecl *Func);
  FunctionExceptionInfo analyzeFunctionImpl(const FunctionDecl *Func);
  FunctionExceptionInfo analyzeStatementImpl(const Stmt *S);

  /// Configure the analyzer to ignore std::bad_alloc exceptions
  void ignoreBadAlloc(bool Value) { IgnoreBadAlloc_ = Value; }

  /// Configure the analyzer to ignore specific exception types
  void ignoreExceptions(const std::vector<std::string> &Types) {
    IgnoredExceptions_ = Types;
  }

private:
  /// Analyze a statement and update the exception information
  void analyzeStatement(const Stmt *S, FunctionExceptionInfo &Info);

  /// Build a call graph for a function
  void buildCallGraph(const FunctionDecl *Func, FunctionExceptionInfo &Info);

  /// Get conditions under which a throw expression occurs
  std::vector<ExceptionCondition> getConditions(const Stmt *Throw);

  /// Get the parent statement of a given statement
  const Stmt *getParentStmt(const Stmt *S) const;

  ASTContext &Context_;         ///< AST context
  bool IgnoreBadAlloc_ = false; ///< Whether to ignore std::bad_alloc
  std::vector<std::string> IgnoredExceptions_; ///< Exception types to ignore
  llvm::DenseMap<const FunctionDecl *, FunctionExceptionInfo> FunctionCache_;
  llvm::DenseMap<const FunctionDecl *, llvm::SmallSet<const FunctionDecl *, 8>>
      CallGraphCache_;
  llvm::DenseMap<const FunctionDecl *, std::vector<ExceptionCondition>>
      ConditionCache_;
  llvm::DenseMap<const Stmt *, const Stmt *>
      ParentMap_; ///< Maps statements to their parents
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYZER_H