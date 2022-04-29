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
#include <sstream>
#include <string>

using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::cross_tu;
using namespace clang::tooling;

static cl::OptionCategory
    ClangExtDefMapGenCategory("clang-extdefmapgen options");

struct CallInfo {
  const CallExpr* Expr;
  std::string Name;
};

struct ThrowInfo {
  const CXXThrowExpr* Expr;
};

struct CatchInfo {
  const CXXCatchStmt* Stmt;
};

struct ExceptionInfo {
  llvm::SmallVector<ThrowInfo> Throws;
  llvm::SmallVector<CatchInfo> Catches;
  llvm::SmallVector<CallInfo> Calls;
};

StatementMatcher CallMatcher = findAll(callExpr().bind("call"));
StatementMatcher ThrowMatcher = findAll(cxxThrowExpr().bind("throw"));
StatementMatcher CatchMatcher = findAll(cxxCatchStmt().bind("catch"));

class ExceptionInfoConsumer {
public:
  ExceptionInfoConsumer(ExceptionInfo& EI): EI(EI) {}
protected:
  ExceptionInfo& EI;
};

class CalledFunctions : public ExceptionInfoConsumer, public MatchFinder::MatchCallback {
public :
  CalledFunctions(ExceptionInfo& EI): ExceptionInfoConsumer(EI) {}
  virtual void run(const MatchFinder::MatchResult &Result) override {
    if (const CallExpr *Call = Result.Nodes.getNodeAs<clang::CallExpr>("call")) {
      llvm::errs() << "call\n";
      if (const auto* ND = dyn_cast<NamedDecl>(Call->getCalleeDecl()) ) {
        if (const Optional<std::string> Name = CrossTranslationUnitContext::getLookupName(ND))
          EI.Calls.push_back({Call, *Name});
      }
    }
  }
};

class ThrownExceptions : public ExceptionInfoConsumer, public MatchFinder::MatchCallback {
public :
  ThrownExceptions(ExceptionInfo& EI): ExceptionInfoConsumer(EI) {}
  virtual void run(const MatchFinder::MatchResult &Result) override {
    if (const CXXThrowExpr *Throw = Result.Nodes.getNodeAs<clang::CXXThrowExpr>("throw")) {
      llvm::errs() << "throw\n";
      EI.Throws.push_back({Throw});
    }
  }
};

class CaughtExceptions : public ExceptionInfoConsumer, public MatchFinder::MatchCallback {
public :
  CaughtExceptions(ExceptionInfo& EI): ExceptionInfoConsumer(EI) {}
  virtual void run(const MatchFinder::MatchResult &Result) override {
    if (const CXXCatchStmt *Catch = Result.Nodes.getNodeAs<clang::CXXCatchStmt>("catch")) {
      llvm::errs() << "catch\n";
      EI.Catches.push_back({Catch});
    }
  }
};

class FunctionMapConsumer : public ASTConsumer {
public:
  FunctionMapConsumer(ASTContext &Context, llvm::StringMap<ExceptionInfo> &Index)
      : AC(Context), SM(Context.getSourceManager()), Index(Index) {}

  ~FunctionMapConsumer() {
    // Flush results to standard output.
    // llvm::errs() << createCrossTUIndexString(Index);
  }

  void HandleTranslationUnit(ASTContext &Context) override {
    handleDecl(Context.getTranslationUnitDecl());
  }

private:
  void handleFunctionBody(std::string CallerName, const Stmt* Body) {
    MatchFinder MF;
    ExceptionInfo EI;
    auto CallAction = std::make_unique<CalledFunctions>(EI);
    auto ThrowAction = std::make_unique<ThrownExceptions>(EI);
    auto CatchAction = std::make_unique<CaughtExceptions>(EI);
    MF.addMatcher(CallMatcher, CallAction.get());
    MF.addMatcher(ThrowMatcher, ThrowAction.get());
    MF.addMatcher(CatchMatcher, CatchAction.get());
    MF.match(*Body, AC);
    Index[CallerName] = EI;
  }

  void handleDecl(const Decl *D) {
    if (!D)
      return;

    if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
      if (FD->isThisDeclarationADefinition()) {
        if (const Stmt *Body = FD->getBody()) {
          if (SM.isInMainFile(Body->getBeginLoc())) {
            llvm::Optional<std::string> LookupName =
              CrossTranslationUnitContext::getLookupName(FD);
            if (LookupName)
              handleFunctionBody(*LookupName, Body);
          }
        }
      }
    }

    if (const DeclContext* DC = dyn_cast<DeclContext>(D)) {
      for (const Decl* SubDecl: DC->decls()) {
        handleDecl(SubDecl);
      }
    }
  }

  ASTContext &AC;
  SourceManager &SM;
  llvm::StringMap<ExceptionInfo> &Index;
  std::string CurrentFileName;
};

class CollectFunctionDeclsAction : public ASTFrontendAction {
public:
  CollectFunctionDeclsAction(llvm::StringMap<ExceptionInfo> &Index)
      : Index(Index) {}

protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 llvm::StringRef) override {
    return std::make_unique<FunctionMapConsumer>(CI.getASTContext(), Index);
  }

private:
  llvm::StringMap<ExceptionInfo> &Index;
};

std::unique_ptr<FrontendActionFactory>
newCollectFunctionDeclsFactory(llvm::StringMap<ExceptionInfo> &Index) {
  class CollectFunctionDecslActionFactory : public FrontendActionFactory {
  public:
    CollectFunctionDecslActionFactory(llvm::StringMap<ExceptionInfo> &Index)
        : Index(Index) {}
    std::unique_ptr<FrontendAction> create() override {
      return std::make_unique<CollectFunctionDeclsAction>(Index);
    }

  private:
    llvm::StringMap<ExceptionInfo> &Index;
  };

  return std::unique_ptr<FrontendActionFactory>(
      new CollectFunctionDecslActionFactory(Index));
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

  llvm::StringMap<ExceptionInfo> Index;
  auto FunctionCollector = std::make_unique<CollectFunctionDeclsAction>(Index);

  int result = Tool.run(newCollectFunctionDeclsFactory(Index).get());

  llvm::errs() << '\n';
  for (const auto& Function: Index) {
    llvm::errs() << Function.first() << ":\n";
    llvm::errs() << "  calls:\n";
    for (const CallInfo& Call: Function.second.Calls) {
      llvm::errs() << "    - " << Call.Name << "\n";
    }
    llvm::errs() << "  throws:\n";
    for (const ThrowInfo& Throw: Function.second.Throws) {
      llvm::errs() << "    - " << Throw.Expr->getType().getAsString() << "\n";
    }
    llvm::errs() << "  catches:\n";
    for (const CatchInfo& Catch: Function.second.Catches) {
      llvm::errs() << "    - " << Catch.Stmt->getCaughtType().getAsString() << "\n";
    }
  }

  return result;
}
