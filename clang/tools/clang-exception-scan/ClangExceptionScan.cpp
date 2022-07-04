//===- ClangExtDefMapGen.cpp
//-----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===--------------------------------------------------------------------===//
//
// Clang tool which creates a list of defined functions and the files in which
// they are defined.
//
//===--------------------------------------------------------------------===//

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Signals.h"
#include <queue>
#include <sstream>
#include <string>
#include <unordered_map>

using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::cross_tu;
using namespace clang::tooling;

static cl::OptionCategory
    ClangExtDefMapGenCategory("clang-extdefmapgen options");

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

  // std::set<const FunctionDecl *> AlreadyVisitedFunctions;
  // std::set<std::pair<const FunctionDecl *, const FunctionDecl *>>
  //    AlreadyVisitedPairs;
  // std::queue<const FunctionDecl *> FunctionWorklist;
};

StatementMatcher CallMatcher = findAll(invocation().bind("invocation"));
StatementMatcher ThrowMatcher = findAll(cxxThrowExpr().bind("throw"));
StatementMatcher CatchMatcher = findAll(cxxCatchStmt().bind("catch"));
StatementMatcher TryMatcher = findAll(cxxTryStmt().bind("try"));

Optional<bool> isInside(Stmt *Candidate, Stmt *Container) {
  SourceRange CandidateRange = Candidate->getSourceRange();
  SourceRange ContainerRange = Container->getSourceRange();

  if (CandidateRange.isInvalid() || ContainerRange.isInvalid())
    return None;

  return ContainerRange.fullyContains(CandidateRange);
}

class ExceptionInfoConsumer {
public:
  ExceptionInfoConsumer(ExceptionInfo &EI, SourceManager &SM)
      : EI(EI), SM(SM) {}

protected:
  ExceptionInfo &EI;
  SourceManager &SM;
};

class CalledFunctions : public ExceptionInfoConsumer,
                        public MatchFinder::MatchCallback {
public:
  CalledFunctions(ExceptionInfo &EI, SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void run(const MatchFinder::MatchResult &Result) override {
    const Expr *Expr = nullptr;
    const FunctionDecl *Callee = nullptr;

    if (const CallExpr *Call =
            Result.Nodes.getNodeAs<clang::CallExpr>("invocation")) {
      Expr = Call;
      Callee = Call->getDirectCallee();
    } else if (const CXXConstructExpr *CTOR =
                   Result.Nodes.getNodeAs<clang::CXXConstructExpr>(
                       "invocation")) {
      Expr = CTOR;
      Callee = CTOR->getConstructor();
    }

    if (!Expr || !Callee) {
      return;
    }

    std::string Name =
        CrossTranslationUnitContext::getLookupName(Callee).getValueOr(
            "<no-lookup-name>");
    EI.Calls.push_back(
        {Expr, Callee, Name, Expr->getSourceRange().printToString(SM)});
  }
};

class ThrownExceptions : public ExceptionInfoConsumer,
                         public MatchFinder::MatchCallback {
public:
  ThrownExceptions(ExceptionInfo &EI, SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void run(const MatchFinder::MatchResult &Result) override {
    if (const CXXThrowExpr *Throw =
            Result.Nodes.getNodeAs<clang::CXXThrowExpr>("throw")) {
      bool IsRethrow = Throw->getSubExpr() == nullptr;
      std::string Description;
      if (IsRethrow)
        Description = "rethrow";
      else {
        const QualType CT = Throw->getSubExpr()->getType();
        if (CT.isNull()) {
          Description = "nulltype";
        } else {
          Description = CT.getAsString();
        }
      }
      EI.Throws.push_back({Throw, IsRethrow, Description,
                           Throw->getSourceRange().printToString(SM)});
    }
  }
};

class CaughtExceptions : public ExceptionInfoConsumer,
                         public MatchFinder::MatchCallback {
public:
  CaughtExceptions(ExceptionInfo &EI, SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void run(const MatchFinder::MatchResult &Result) override {
    if (const CXXCatchStmt *Catch =
            Result.Nodes.getNodeAs<clang::CXXCatchStmt>("catch")) {
      bool IsCatchAll = Catch->getExceptionDecl() == nullptr;
      std::string Description;
      if (IsCatchAll)
        Description = "...";
      else {
        const QualType CT = Catch->getExceptionDecl()->getType();
        if (CT.isNull()) {
          Description = "nulltype";
        } else {
          Description = CT.getAsString();
        }
      }
      EI.Catches.push_back({Catch, IsCatchAll, Description,
                            Catch->getSourceRange().printToString(SM)});
    }
  }
};

class TryBlocks : public ExceptionInfoConsumer,
                  public MatchFinder::MatchCallback {
public:
  TryBlocks(ExceptionInfo &EI, SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void run(const MatchFinder::MatchResult &Result) override {
    if (const CXXTryStmt *Try =
            Result.Nodes.getNodeAs<clang::CXXTryStmt>("try")) {
      EI.Tries.push_back({Try, Try->getSourceRange().printToString(SM)});
    }
  }
};

class FunctionMapConsumer : public ASTConsumer {
public:
  FunctionMapConsumer(ASTContext &Context, ExceptionContext &EC)
      : AC(Context), SM(Context.getSourceManager()), EC(EC) {}

  ~FunctionMapConsumer() {
    // Flush results to standard output.
    // llvm::errs() << createCrossTUIndexString(Index);
  }

  void HandleTranslationUnit(ASTContext &Context) override {
    handleDecl(Context.getTranslationUnitDecl());
  }

private:
  void handleFunction(const FunctionDecl *FD) {
    EC.FunctionsVisited.insert(FD);

    llvm::Optional<std::string> LookupName =
        CrossTranslationUnitContext::getLookupName(FD);
    std::string CallerName = LookupName.getValueOr("<no-name>");
    EC.NameIndex[FD] = CallerName;
    EC.ShortNameIndex[FD] = FD->getNameAsString();
    const Stmt *Body = FD->getBody();
    if (!Body)
      return;
    EC.BodyIndex[FD] = Body;
    EC.IsInMainFileIndex[FD] = SM.isInMainFile(FD->getLocation());

    MatchFinder MF;
    ExceptionInfo EI;
    auto CallAction = std::make_unique<CalledFunctions>(EI, SM);
    auto ThrowAction = std::make_unique<ThrownExceptions>(EI, SM);
    auto CatchAction = std::make_unique<CaughtExceptions>(EI, SM);
    auto TryAction = std::make_unique<TryBlocks>(EI, SM);
    MF.addMatcher(CallMatcher, CallAction.get());
    MF.addMatcher(ThrowMatcher, ThrowAction.get());
    MF.addMatcher(CatchMatcher, CatchAction.get());
    MF.addMatcher(TryMatcher, TryAction.get());
    MF.match(*Body, AC);

    EC.ExInfoIndex[FD] = EI;

    for (const CallInfo &CI : EI.Calls) {
      const FunctionDecl *Callee = CI.Callee;
      if (!SeenFunctions.count(Callee)) {
        SeenFunctions.insert(Callee);
        ExplorationWorklist.push(Callee);
      }
    }
  }

  void handleDecl(const Decl *D) {
    if (!D)
      return;

    if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
      handleFunction(FD);
    }

    if (const DeclContext *DC = dyn_cast<DeclContext>(D)) {
      for (const Decl *SubDecl : DC->decls()) {
        handleDecl(SubDecl);
      }
    }

    while (!ExplorationWorklist.empty()) {
      const FunctionDecl *FD = ExplorationWorklist.front();
      handleFunction(FD);
      ExplorationWorklist.pop();
    }
  }

  ASTContext &AC;
  SourceManager &SM;
  ExceptionContext &EC;
  std::set<const FunctionDecl *> SeenFunctions;
  std::queue<const FunctionDecl *> ExplorationWorklist;
};

class CollectFunctionDeclsAction : public ASTFrontendAction {
public:
  CollectFunctionDeclsAction(ExceptionContext &Index) : Index(Index) {}

protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 llvm::StringRef) override {
    return std::make_unique<FunctionMapConsumer>(CI.getASTContext(), Index);
  }

private:
  ExceptionContext &Index;
};

std::unique_ptr<FrontendActionFactory>
newCollectFunctionDeclsFactory(ExceptionContext &EC) {
  class CollectFunctionDecslActionFactory : public FrontendActionFactory {
  public:
    CollectFunctionDecslActionFactory(ExceptionContext &EC) : EC(EC) {}
    std::unique_ptr<FrontendAction> create() override {
      return std::make_unique<CollectFunctionDeclsAction>(EC);
    }

  private:
    ExceptionContext &EC;
  };

  return std::unique_ptr<FrontendActionFactory>(
      new CollectFunctionDecslActionFactory(EC));
}

static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);

int main(int argc, const char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0], false);
  PrettyStackTraceProgram X(argc, argv);

  const char *Overview = "\nThis tool exception information from a project.\n";
  auto ExpectedParser = CommonOptionsParser::create(
      argc, argv, ClangExtDefMapGenCategory, cl::ZeroOrMore, Overview);
  if (!ExpectedParser) {
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }
  CommonOptionsParser &OptionsParser = ExpectedParser.get();

  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());

  ExceptionContext EC;
  auto FunctionCollector = std::make_unique<CollectFunctionDeclsAction>(EC);

  int result = Tool.run(newCollectFunctionDeclsFactory(EC).get());

  bool ShowLocation = true;

  llvm::errs() << '\n';
  for (const auto &FD : EC.FunctionsVisited) {

    if (!EC.IsInMainFileIndex[FD])
      continue;

    std::set<const FunctionDecl *> Seen;
    auto rec_print_ei = [&](const FunctionDecl *FD, int level = 0) {
      auto rec_print_ei_impl = [&](const FunctionDecl *FD, int level,
                                   auto &rec_ref) -> void {
        // if (Seen.count(FD))
        //   return;
        // Seen.insert(FD);

        std::string indent(2 * level, ' ');

        if (level == 0) {
          llvm::errs() << indent << "Name:\n";
          llvm::errs() << indent << EC.ShortNameIndex[FD] << "\n";
        }

        const ExceptionInfo &EI = EC.ExInfoIndex[FD];
        if (!EI.Tries.empty()) {
          llvm::errs() << indent << "tries:\n";

          for (const TryInfo &Try : EI.Tries) {
            llvm::errs() << indent << "  - " << Try.Stmt;
            if (ShowLocation)
              llvm::errs() << "@" << Try.Location;
            llvm::errs() << "\n";
          }
        }

        if (!EI.Throws.empty()) {
          llvm::errs() << indent << "throws:\n";
          for (const ThrowInfo &Throw : EI.Throws) {
            llvm::errs() << indent << "  - " << Throw.Description;
            if (ShowLocation)
              llvm::errs() << "@" << Throw.Location;
            llvm::errs() << "\n";
          }
        }

        if (!EI.Catches.empty()) {
          llvm::errs() << indent << "catches:\n";
          for (const CatchInfo &Catch : EI.Catches) {
            llvm::errs() << indent << "  - " << Catch.Description;

            if (ShowLocation)
              llvm::errs() << "@" << Catch.Location;
            llvm::errs() << "\n";
          }
        }

        if (!EI.Calls.empty()) {
          llvm::errs() << indent << "calls:\n";
          for (const CallInfo &Call : EI.Calls) {
            llvm::errs() << indent << "  - " << EC.ShortNameIndex[Call.Callee];
            if (ShowLocation)
              llvm::errs() << "@" << Call.Location;
            llvm::errs() << "\n";

            rec_ref(Call.Callee, level + 1, rec_ref);
          }
        }
      };
      rec_print_ei_impl(FD, level, rec_print_ei_impl);
    };

    rec_print_ei(FD);
  }

  return result;
}
