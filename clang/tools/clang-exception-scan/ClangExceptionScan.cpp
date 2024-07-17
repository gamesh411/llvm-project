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
#include "clang/AST/ASTDumper.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/SourceManager.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Signals.h"
#include <clang/Analysis/CallGraph.h>
#include <optional>
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

std::optional<bool> isInside(const Stmt *Candidate, const Stmt *Container) {
  SourceRange CandidateRange = Candidate->getSourceRange();
  SourceRange ContainerRange = Container->getSourceRange();

  if (CandidateRange.isInvalid() || ContainerRange.isInvalid())
    return std::nullopt;

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
        CrossTranslationUnitContext::getLookupName(Callee).value_or(
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
    // llvm::outs() << createCrossTUIndexString(Index);
  }

  void HandleTranslationUnit(ASTContext &Context) override {
    handleDecl(Context.getTranslationUnitDecl());
  }

private:
  void handleFunction(const FunctionDecl *FD) {

    llvm::outs() << "Function: \n";
    FD->print(llvm::outs());
    llvm::outs() << "\n";

    llvm::outs() << "Postorder callees: \n";
    clang::CallGraph CG;
    CG.addToCallGraph(const_cast<TranslationUnitDecl *>(FD->getTranslationUnitDecl()));

    std::set<CallGraphNode *> SeenNodes;
    std::vector<CallGraphNode *> Postorder;

    auto postorder = [&](CallGraphNode *Node) {
      auto postorder_impl = [&](CallGraphNode *Node, auto &impl) -> void {
        Node->dump();
        SeenNodes.insert(Node);
        for (CallGraphNode::iterator I = Node->begin(), E = Node->end(); I != E;
             ++I) {
          CallGraphNode *Callee = *I;
          if (SeenNodes.count(Callee) == 0) {
            impl(Callee, impl);
          }
        }
        Postorder.push_back(Node);
      };
      postorder_impl(Node, postorder_impl);
    };

    postorder(CG.getNode(FD));

    for (CallGraphNode *Node : Postorder) {
      llvm::outs() << "Node: ";
      Node->print(llvm::outs());
      llvm::outs() << "\n";
    }

    return;

    EC.FunctionsVisited.insert(FD);

    std::optional<std::string> LookupName =
        CrossTranslationUnitContext::getLookupName(FD);
    std::string CallerName = LookupName.value_or("<no-name>");
    EC.NameIndex[FD] = CallerName;
    EC.ShortNameIndex[FD] = FD->getNameAsString();
    Stmt *Body = FD->getBody();
    if (!Body)
      return;

    auto BO = clang::CFG::BuildOptions{};
    BO.AddEHEdges = true;
    // BO.setAllAlwaysAdd();

    std::unique_ptr<CFG> FDCFG = clang::CFG::buildCFG(FD, Body, &AC, BO);

    if (!FDCFG) {
      return;
    }

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

      auto [_, emplaced] = SeenFunctions.insert(Callee);
      if (emplaced) {
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

int main(int argc, const char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);

  if (argc != 2) {
    llvm::errs() << "Usage: clang-exception-scan <compdb>";
    return 1;
  }

  const auto *CompDBPath = argv[1];
  auto ErrorMessage = std::string{};
  auto CompDB = JSONCompilationDatabase::loadFromFile(
      CompDBPath, ErrorMessage, JSONCommandLineSyntax::AutoDetect);

  llvm::outs() << "Loading compilation database " << CompDBPath << "...\n";

  if (!CompDB) {
    llvm::errs() << ErrorMessage;
    return 2;
  }

  llvm::outs() << "Compilation database " << argv[1] << " loaded.\n";

  const auto &Files = CompDB->getAllFiles();
  const auto UniqueFiles = std::set<std::string>{Files.begin(), Files.end()};

  if (Files.size() != UniqueFiles.size()) {
    llvm::errs() << "Files list in compilation database is not unique!";
    return 3;
  }

  llvm::outs() << "Files to process:\n";

  for (const auto &F : Files)
    llvm::outs() << F << '\n';

  llvm::outs() << "\n";

  ClangTool Tool(*CompDB, CompDB->getAllFiles());

  ExceptionContext EC;
  auto FunctionCollector = std::make_unique<CollectFunctionDeclsAction>(EC);

  int result = Tool.run(newCollectFunctionDeclsFactory(EC).get());

  bool ShowLocation = true;

  llvm::outs() << '\n';
  for (const auto &FD : EC.FunctionsVisited) {

    if (!EC.IsInMainFileIndex[FD])
      continue;

    const ExceptionInfo &EI = EC.ExInfoIndex[FD];

    auto UncaughtThrows = EI.Throws;

    auto rec_print_ei = [&](const FunctionDecl *FD, int level = 0) {
      llvm::outs() << "Function:\n";

      // ASTDumper P(llvm::outs(), /*ShowColors=*/false);
      // P.Visit(FD->getBody());

      auto rec_print_ei_impl = [&](const FunctionDecl *FD, int level,
                                   auto &rec_ref) -> void {
        std::string indent(2 * level, ' ');

        if (level == 0) {
          llvm::outs() << indent << "Name:\n";
          llvm::outs() << indent << EC.ShortNameIndex[FD] << "\n";
        }

        if (!EI.Tries.empty()) {
          llvm::outs() << indent << "tries:\n";

          for (const TryInfo &Try : EI.Tries) {
            llvm::outs() << indent << "  - " << Try.Stmt;
            if (ShowLocation)
              llvm::outs() << "@" << Try.Location;
            llvm::outs() << "\n";
          }
        }

        if (!EI.Throws.empty()) {
          for (const ThrowInfo &Throw : EI.Throws) {
            // if a throw statement is inside a try statement, then
            // lets examine all the catch statements, and if a catch statement
            // matches the throw type, then lets remove the throw statement
            // from the list of throws.
            // FIXME: this is ugly
            for (const TryInfo &Try : EI.Tries) {
              if (isInside(Throw.Expr, Try.Stmt)) {
                for (const CatchInfo &Catch : EI.Catches) {
                  if (isInside(Catch.Stmt, Try.Stmt)) {
                    if (Catch.Stmt->getCaughtType() ==
                        Throw.Expr->getSubExpr()->getType()) {
                      const auto &AsConst = std::as_const(UncaughtThrows);
                      UncaughtThrows.erase(
                          std::find_if(AsConst.begin(), AsConst.end(),
                                       [TE = Throw.Expr](const ThrowInfo &TI) {
                                         return TE == TI.Expr;
                                       }));
                    }
                  }
                }
              }
            }
          }

          llvm::outs() << indent << "uncaught throws:\n";
          for (const ThrowInfo &Throw : UncaughtThrows) {
            llvm::outs() << indent << "  - " << Throw.Description;
            if (ShowLocation)
              llvm::outs() << "@" << Throw.Location;
            llvm::outs() << "\n";
          }
        }

        if (!EI.Catches.empty()) {
          llvm::outs() << indent << "catches:\n";
          for (const CatchInfo &Catch : EI.Catches) {
            llvm::outs() << indent << "  - " << Catch.Description;

            if (ShowLocation)
              llvm::outs() << "@" << Catch.Location;
            llvm::outs() << "\n";
          }
        }

        if (!EI.Calls.empty()) {
          llvm::outs() << indent << "calls:\n";
          for (const CallInfo &Call : EI.Calls) {
            llvm::outs() << indent << "  - " << EC.ShortNameIndex[Call.Callee];
            if (ShowLocation)
              llvm::outs() << "@" << Call.Location;
            llvm::outs() << "\n";

            //rec_ref(Call.Callee, level + 1, rec_ref);
          }
        }
      };
      rec_print_ei_impl(FD, level, rec_print_ei_impl);
    };

    rec_print_ei(FD);

    // exception specification if noexcept false if there are any uncaught
    // throws, otherwise it is the and-combined noexcept specification of the
    // called functions
    llvm::outs() << "Exception specification:\n";

    llvm::outs() << "  noexcept";
    if (FD->getExceptionSpecType() == clang::EST_BasicNoexcept ||
        FD->getExceptionSpecType() == clang::EST_NoexceptTrue) {
      continue;
    }

    auto PotentiallyThrowingCalls = llvm::SmallVector<const FunctionDecl *>();
    for (const auto &Call : EI.Calls) {
      if (Call.Callee->getExceptionSpecType() == clang::EST_BasicNoexcept ||
          Call.Callee->getExceptionSpecType() == clang::EST_NoexceptTrue) {
        continue;
      }
      PotentiallyThrowingCalls.push_back(Call.Callee);
    }
    if (PotentiallyThrowingCalls.empty()) {
      continue;
    }
    llvm::outs() << "(";
    bool first = true;
    for (const auto &Call : PotentiallyThrowingCalls) {
      if (!first) {
        llvm::outs() << " && ";
      }
      first = false;
      llvm::outs() << "noexcept(";
      llvm::outs() << EC.ShortNameIndex[Call] << "()";
      llvm::outs() << ")";
    }
    llvm::outs() << ")";
  }

  return result;
}
