#pragma once

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>

namespace clang {
namespace exception_scan {

struct CallInfo {
  const Expr *CallOrCtorInvocation;
  const FunctionDecl *Callee;
  std::string Name;
  std::string Location;
};

struct ThrowInfo {
  const CXXThrowExpr *Expr;
  std::string Description;
  std::string Location;
  bool isRethrow;
};

struct CatchInfo {
  const CXXCatchStmt *Stmt;
  std::string Description;
  std::string Location;
  bool isCatchAll;
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

std::optional<bool> isInside(const Stmt *Candidate, const Stmt *Container);

class ExceptionInfoConsumer {
protected:
  ExceptionInfoConsumer(ExceptionInfo &EI, SourceManager &SM)
      : EI(EI), SM(SM) {}

  ExceptionInfo &EI;
  SourceManager &SM;
};

class CalledFunctions : public ExceptionInfoConsumer,
                       public ast_matchers::MatchFinder::MatchCallback {
public:
  CalledFunctions(ExceptionInfo &EI, SourceManager &SM);
  void run(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

class ThrownExceptions : public ExceptionInfoConsumer,
                        public ast_matchers::MatchFinder::MatchCallback {
public:
  ThrownExceptions(ExceptionInfo &EI, SourceManager &SM);
  void run(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

class CaughtExceptions : public ExceptionInfoConsumer,
                        public ast_matchers::MatchFinder::MatchCallback {
public:
  CaughtExceptions(ExceptionInfo &EI, SourceManager &SM);
  void run(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

class TryBlocks : public ExceptionInfoConsumer,
                  public ast_matchers::MatchFinder::MatchCallback {
public:
  TryBlocks(ExceptionInfo &EI, SourceManager &SM);
  void run(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

class ExceptionInfoASTConsumer : public ASTConsumer {
public:
  ExceptionInfoASTConsumer(ASTContext &Context, ExceptionContext &EC);
  void HandleTranslationUnit(ASTContext &Context) override;

private:
  void handleFunction(const FunctionDecl *FD);
  void handleDecl(const Decl *D);

  ASTContext &AC;
  SourceManager &SM;
  ExceptionContext &EC;
  std::set<const FunctionDecl *> SeenFunctions;
  std::queue<const FunctionDecl *> ExplorationWorklist;
};

class CollectExceptionInfoAction : public ASTFrontendAction {
public:
  CollectExceptionInfoAction(ExceptionContext &Index);
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                StringRef) override;

private:
  ExceptionContext &Index;
};

class CollectExceptionInfoActionFactory : public tooling::FrontendActionFactory {
public:
  std::unique_ptr<FrontendAction> create() override;
  ExceptionContext EC;
  virtual ~CollectExceptionInfoActionFactory() = default;
};

} // namespace exception_scan
} // namespace clang
