#pragma once

#include "llvm/ADT/SmallVector.h"
#include <set>
#include <string>
#include <unordered_map>

namespace clang {
  class CXXCatchStmt;
  class CXXThrowExpr;
  class CXXTryStmt;
  class Expr;
  class FunctionDecl;
  class Stmt;
} // namespace clang


using namespace clang;

struct CallInfo {
  const Expr *CallOrCtorInvocation;
  const FunctionDecl *Callee;
  std::string Name;
  std::string Location;
};

struct ThrowInfo {
  const CXXThrowExpr *Expr;
  bool isRethrow;
  std::string Description;
  std::string Location;
};

struct CatchInfo {
  const CXXCatchStmt *Stmt;
  bool isCatchAll;
  std::string Description;
  std::string Location;
};

struct TryInfo {
  const CXXTryStmt *Stmt;
  std::string Location;
};

struct ExceptionInfo {
  llvm::SmallVector<ThrowInfo> Throws;
  llvm::SmallVector<CatchInfo> Catches;
  llvm::SmallVector<CallInfo> Calls;
  llvm::SmallVector<TryInfo> Tries;
};

struct ExceptionContext {
  std::set<const FunctionDecl *> FunctionsVisited;
  std::unordered_map<const FunctionDecl *, std::string> NameIndex;
  std::unordered_map<const FunctionDecl *, std::string> ShortNameIndex;
  std::unordered_map<const FunctionDecl *, const Stmt *> BodyIndex;

  std::unordered_map<const FunctionDecl *, bool> IsInMainFileIndex;
  std::unordered_map<const FunctionDecl *, ExceptionInfo> ExInfoIndex;

  std::unordered_map<const FunctionDecl *, const FunctionDecl *> CalleeIndex;
};
