#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_ASTBASEDEXCEPTIONANALYZER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_ASTBASEDEXCEPTIONANALYZER_H

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
#include <optional>
#include <string>
#include <vector>

namespace clang {
namespace exception_scan {

/// AST-based exception analyzer that focuses on try-catch blocks and throw
/// statements
class ASTBasedExceptionAnalyzer {
public:
  explicit ASTBasedExceptionAnalyzer(ASTContext &Context);

  /// Helper struct to represent a try-catch block and its containment
  /// relationships
  struct TryCatchInfo {
    const CXXTryStmt *TryStmt = nullptr;
    std::vector<TryCatchInfo> InnerTryCatches;
    SourceLocation Loc = SourceLocation();
    unsigned int Depth = 0u;

    TryCatchInfo() = default;

    TryCatchInfo(const CXXTryStmt *TS, SourceLocation L, unsigned int D = 0)
        : TryStmt(TS), Loc(L), Depth(D) {}

    bool operator<(const TryCatchInfo &Other) const {
      if (Depth != Other.Depth)
        return Depth > Other.Depth; // Higher depth comes first
      return Loc < Other.Loc;
    }
  };

  struct HierarchicalSourceLocationOrdering {
    bool operator()(const TryCatchInfo &A, const TryCatchInfo &B) const {
      // First order by depth (higher depth first)
      if (A.Depth != B.Depth)
        return A.Depth > B.Depth;

      // For same depth, order by source location
      return A.Loc < B.Loc;
    }
  };

  using AnalysisOrderedTryCatches =
      std::set<TryCatchInfo, HierarchicalSourceLocationOrdering>;

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

  /// Helper functions for testing
  static llvm::DenseMap<const Stmt *, const Stmt *>
  buildParentMap(const Stmt *S);
  static llvm::DenseMap<const Stmt *, llvm::SmallSet<const Stmt *, 4>>
  buildTransitiveParentMap(
      const llvm::DenseMap<const Stmt *, const Stmt *> &ParentMap,
      const Stmt *Root);
  static AnalysisOrderedTryCatches findTryCatchBlocks(const Stmt *S,
                                                      const SourceManager &SM);

private:
  /// Analyze a statement and update the exception information
  void analyzeStatement(const Stmt *S, FunctionExceptionInfo &Info);

  /// Analyze a try-catch block
  void analyzeTryCatch(const CXXTryStmt *Try, FunctionExceptionInfo &Info);

  /// Analyze a catch block
  void analyzeCatchBlock(const CXXCatchStmt *Catch,
                         const std::vector<ThrowInfo> &TryThrowEvents,
                         FunctionExceptionInfo &Info);

  /// Analyze a throw expression
  void analyzeThrowExpr(const CXXThrowExpr *Throw, FunctionExceptionInfo &Info);

  /// Analyze a function call
  void analyzeCallExpr(const CallExpr *Call, FunctionExceptionInfo &Info);

  /// Check if a type can catch another type
  bool canCatchType(QualType CaughtType, QualType ThrownType) const;

  /// Get the unqualified type for comparison
  QualType getUnqualifiedType(QualType Type) const;

  /// Get condition information from an expression
  ExceptionCondition getConditionInfo(const Expr *Cond) const;

  /// Get the parent statement of a given statement
  const Stmt *getParentStmt(const Stmt *S) const;

  /// Build a map of statements to their parents
  void updateParentMap(const Stmt *S);

  ASTContext &Context_;         ///< AST context
  bool IgnoreBadAlloc_ = false; ///< Whether to ignore std::bad_alloc
  std::vector<std::string> IgnoredExceptions_; ///< Exception types to ignore
  llvm::DenseMap<const FunctionDecl *, FunctionExceptionInfo> FunctionCache_;
  llvm::DenseMap<const Stmt *, const Stmt *>
      ParentMap_; ///< Maps statements to their parents
  llvm::DenseMap<const CXXTryStmt *, FunctionExceptionInfo>
      TryBlockCache_; ///< Cache of analyzed try blocks
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_ASTBASEDEXCEPTIONANALYZER_H