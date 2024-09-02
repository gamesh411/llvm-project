#include "CalledFunctionInfoConsumer.hpp"
#include "CaughtExceptionInfoConsumer.hpp"
#include "ExceptionContext.hpp"
#include "ExceptionInfoConsumer.hpp"
#include "ThrownExceptionInfoConsumer.hpp"
#include "TryBlockInfoConsumer.hpp"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/CallGraph.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Tooling/Refactoring/Rename/USRFinder.h"
#include "llvm/ADT/SmallString.h"
#include <queue>
#include <set>

namespace {

class CGBuilder : public StmtVisitor<CGBuilder> {
  CallGraph *G;
  CallGraphNode *CallerNode;

public:
  CGBuilder(CallGraph *g, CallGraphNode *N) : G(g), CallerNode(N) {}

  void VisitStmt(Stmt *S) { VisitChildren(S); }

  Decl *getDeclFromCall(CallExpr *CE) {
    if (FunctionDecl *CalleeDecl = CE->getDirectCallee())
      return CalleeDecl;

    // Simple detection of a call through a block.
    Expr *CEE = CE->getCallee()->IgnoreParenImpCasts();
    if (BlockExpr *Block = dyn_cast<BlockExpr>(CEE)) {
      return Block->getBlockDecl();
    }

    return nullptr;
  }

  void addCalledDecl(Decl *D, Expr *CallExpr) {
    if (G->includeCalleeInGraph(D)) {
      CallGraphNode *CalleeNode = G->getOrInsertNode(D);
      CallerNode->addCallee({CalleeNode, CallExpr});
    }
  }

  void VisitCallExpr(CallExpr *CE) {
    if (Decl *D = getDeclFromCall(CE))
      addCalledDecl(D, CE);
    VisitChildren(CE);
  }

  void VisitLambdaExpr(LambdaExpr *LE) {
    if (FunctionTemplateDecl *FTD = LE->getDependentCallOperator())
      for (FunctionDecl *FD : FTD->specializations())
        G->VisitFunctionDecl(FD);
    else if (CXXMethodDecl *MD = LE->getCallOperator())
      G->VisitFunctionDecl(MD);
  }

  void VisitCXXNewExpr(CXXNewExpr *E) {
    if (FunctionDecl *FD = E->getOperatorNew())
      addCalledDecl(FD, E);
    VisitChildren(E);
  }

  void VisitCXXConstructExpr(CXXConstructExpr *E) {
    CXXConstructorDecl *Ctor = E->getConstructor();
    if (FunctionDecl *Def = Ctor->getDefinition())
      addCalledDecl(Def, E);
    VisitChildren(E);
  }

  // Include the evaluation of the default argument.
  void VisitCXXDefaultArgExpr(CXXDefaultArgExpr *E) { Visit(E->getExpr()); }

  // Include the evaluation of the default initializers in a class.
  void VisitCXXDefaultInitExpr(CXXDefaultInitExpr *E) { Visit(E->getExpr()); }

  // Adds may-call edges for the ObjC message sends.
  void VisitObjCMessageExpr(ObjCMessageExpr *ME) {
    if (ObjCInterfaceDecl *IDecl = ME->getReceiverInterface()) {
      Selector Sel = ME->getSelector();

      // Find the callee definition within the same translation unit.
      Decl *D = nullptr;
      if (ME->isInstanceMessage())
        D = IDecl->lookupPrivateMethod(Sel);
      else
        D = IDecl->lookupPrivateClassMethod(Sel);
      if (D) {
        addCalledDecl(D, ME);
      }
    }
  }

  void VisitChildren(Stmt *S) {
    for (Stmt *SubStmt : S->children())
      if (SubStmt)
        this->Visit(SubStmt);
  }
};

inline clang::ast_matchers::StatementMatcher CallMatcher =
    clang::ast_matchers::findAll(
        clang::ast_matchers::invocation().bind("invocation"));
inline clang::ast_matchers::StatementMatcher ThrowMatcher =
    clang::ast_matchers::findAll(
        clang::ast_matchers::cxxThrowExpr().bind("throw"));
inline clang::ast_matchers::StatementMatcher CatchMatcher =
    clang::ast_matchers::findAll(
        clang::ast_matchers::cxxCatchStmt().bind("catch"));
inline clang::ast_matchers::StatementMatcher TryMatcher =
    clang::ast_matchers::findAll(clang::ast_matchers::cxxTryStmt().bind("try"));

} // namespace

class ClangExceptionScanConsumer : public clang::ASTConsumer {
public:
  ClangExceptionScanConsumer(clang::ASTContext &Context, ExceptionContext &EC)
      : AC(Context), SM(Context.getSourceManager()), EC(EC) {}

  ~ClangExceptionScanConsumer() {}

  void HandleTranslationUnit(ASTContext &Context) override {
    handleDecl(Context.getTranslationUnitDecl());
  }

private:
  std::string getUSRForDecl(const Decl *Decl) {
    llvm::SmallString<128> Buff;

    if (Decl == nullptr || clang::index::generateUSRForDecl(Decl, Buff))
      return "";

    return std::string(Buff);
  }

  static bool isNoexceptBecauseOfSpecifier(const CallInfo &CI) {
    switch (CI.Callee->getExceptionSpecType()) {
    case EST_None:              ///< no exception specification
    case EST_Dynamic:           ///< throw(T1, T2)
    case EST_MSAny:             ///< Microsoft throw(...) extension
    case EST_DependentNoexcept: ///< noexcept(expression),
                                ///< value-dependent
    case EST_NoexceptFalse:     ///< noexcept(expression), evals to
                                ///< 'false'
    case EST_Unevaluated:       ///< not evaluated yet, for special member
                                ///< function
    case EST_Uninstantiated:    ///< not instantiated yet
    case EST_Unparsed:          ///< not parsed yet
      return false;
    case EST_DynamicNone:   ///< throw()
    case EST_NoThrow:       ///< Microsoft __declspec(nothrow) extension
    case EST_BasicNoexcept: ///< noexcept
    case EST_NoexceptTrue:  ///< noexcept(expression), evals to 'true'
      return true;
    }
  }

  void handleFunction(FunctionDecl *FD) {
    if (!FD->hasBody()) {
      llvm::outs() << "Skipping function without body: " << getUSRForDecl(FD)
                   << "\n";
      return;
    }

    // refactor: CFG building
    auto BO = clang::CFG::BuildOptions{};
    BO.AddEHEdges = true;
    BO.PruneTriviallyFalseEdges = true;

    std::unique_ptr<CFG> FDCFG =
        clang::CFG::buildCFG(FD, FD->getBody(), &AC, BO);

    if (!FDCFG) {
      llvm::outs() << "Skipping function without CFG: " << getUSRForDecl(FD)
                   << "\n";
      return;
    }

    FDCFG->viewCFG(LangOptions());

    EC.BodyIndex[FD] = FD->getBody();
    EC.IsInMainFileIndex[FD] = SM.isInMainFile(FD->getLocation());

    clang::ast_matchers::MatchFinder MF;
    ExceptionInfo EI;
    auto CallAction = std::make_unique<CalledFunctionInfoConsumer>(EI, SM);
    auto ThrowAction = std::make_unique<ThrownExceptionInfoConsumer>(EI, SM);
    auto CatchAction = std::make_unique<CaughtExceptionInfoConsumer>(EI, SM);
    auto TryAction = std::make_unique<TryBlockInfoConsumer>(EI, SM);
    MF.addMatcher(CallMatcher, CallAction.get());
    MF.addMatcher(ThrowMatcher, ThrowAction.get());
    MF.addMatcher(CatchMatcher, CatchAction.get());
    MF.addMatcher(TryMatcher, TryAction.get());
    MF.match(*FD->getBody(), AC);

    llvm::outs() << "Tries before sort:\n";
    std::for_each(EI.Tries.begin(), EI.Tries.end(), [this](auto &&Try) {
      llvm::outs() << Try.Stmt->getSourceRange().printToString(
                          AC.getSourceManager())
                   << "\n";
    });

    llvm::sort(EI.Tries, [](auto &A, auto &B) {
      return B.Stmt->getSourceRange().fullyContains(A.Stmt->getSourceRange());
    });

    llvm::outs() << "Tries after sort:\n";
    std::for_each(EI.Tries.begin(), EI.Tries.end(), [this](auto &&Try) {
      llvm::outs() << Try.Stmt->getSourceRange().printToString(
                          AC.getSourceManager())
                   << "\n";
    });

    llvm::outs() << "Calls:\n";
    for (auto &&CI : EI.Calls) {
      if (isNoexceptBecauseOfSpecifier(CI)) {
        llvm::outs() << ": " << CI.Name << "\n";
      } else {
        llvm::outs() << CI.Name << "\n";
      }
    }

#if 0
    // refactor: Dataflow analysis

    // dataflow domain for statements
    struct PotentialThrows {
      std::set<const Expr *> ThrowingExprs;
      std::map<const Expr *, const Expr *> PotentialCatchesForStmt;
    };

    // calculate the potential throws that can be thrown from an upstream
    // location in the CFG.
    auto &Entry = FDCFG->getEntry();
    std::set<const CFGBlock *> SeenBlocks;
    std::queue<const CFGBlock *> Worklist;

    // Push tht entry block to the worklist:
    // Worklist.push(&Entry);
    // vs only push the successors:
    for (auto &&Starts : Entry.succs()) {
      Worklist.push(Starts);
      SeenBlocks.insert(Starts);
    }

    std::map<const CFGBlock *, PotentialThrows> In;
    std::map<const CFGBlock *, PotentialThrows> Out;

    int CFGBlockCounter = 0;
    while (!Worklist.empty()) {
      const CFGBlock *Current = Worklist.front();
      Worklist.pop();
      SeenBlocks.insert(Current);

      llvm::SmallString<16> BlockName{"CFGBlock"};
      if (Current == &FDCFG->getEntry()) {
        BlockName.append(" entry");
      } else if (Current == &FDCFG->getExit()) {
        BlockName.append(" exit");
      }
      llvm::errs() << "<" << BlockName << "> #" << ++CFGBlockCounter << " @"
                   << Current->getBlockID() << "\n";

      for (auto Pred : Current->preds()) {
        if (!Pred.isReachable())
          continue;
        CFGBlock *Reachable = Pred.getReachableBlock();
        In[Current].ThrowingExprs.insert(Out[Reachable].ThrowingExprs.begin(),
                                         Out[Reachable].ThrowingExprs.end());
      }

      std::set<const Expr *> ToAdd;

      int CFGElementCounter = 0;
      for (auto E = Current->begin(); E != Current->end(); ++E) {
        llvm::errs() << " <CFGElement> #" << ++CFGElementCounter << "\n";
        llvm::errs() << "  <Kind> " << E->getKind() << " </Kind>\n";
        llvm::errs() << "  <Dump>\n";
        E->dump();
        llvm::errs() << "  </Dump>\n";
        if (auto StmtElem = E->getAs<CFGStmt>()) {
          const Stmt *S = StmtElem->getStmt();
          if (const auto *CE = dyn_cast<CallExpr>(S)) {
            const FunctionDecl *CalleeDecl = CE->getDirectCallee();
            if (!CalleeDecl) {
              ToAdd.insert(CE);
            } else {
            }
          } else if (const auto *TE = dyn_cast<CXXThrowExpr>(S)) {
            ToAdd.insert(TE);
          }
        }
        llvm::errs() << " </CFGElement>\n";
      }
      llvm::errs() << "</" << BlockName << ">\n";

      bool Changed = !ToAdd.empty();
      Out[Current].ThrowingExprs.insert(ToAdd.begin(), ToAdd.end());

      for (auto Succ : Current->succs()) {
        if (Succ && (Changed || SeenBlocks.count(Succ) == 0)) {
          Worklist.push(Succ);
        }
      }
    }

    const auto *Exit = &FDCFG->getExit();

    llvm::outs() << "Potential throws reaching the end of execution: ";
    for (const auto *Expr : In[Exit].ThrowingExprs) {
      llvm::outs() << "Expr: ";
      Expr->getSourceRange().print(llvm::outs(), AC.getSourceManager());
      Expr->dumpPretty(AC);
      llvm::outs() << "\n";
    }

#endif

#if 0

    // print throws for statements:
    for (auto *Stmt : FD->getBody()->children()) {
      // print the line of the statement:
      llvm::outs() << "Stmt: ";
      Stmt->getSourceRange().print(llvm::outs(), AC.getSourceManager());
      llvm::outs() << "\n";
      llvm::outs() << "Potential throws: ";
      if (auto ThrowSet = Throws.find(Stmt); ThrowSet != Throws.end()) {
        for (auto ThrowType : ThrowSet->second.ThownTypes) {
          llvm::outs() << ThrowType.getAsString() << " ";
        }
        llvm::outs() << "\n";
      } else {
        llvm::outs() << "none\n";
      }
    }



    EC.FunctionsVisited.insert(FD);

    std::optional<std::string> LookupName =
        cross_tu::CrossTranslationUnitContext::getLookupName(FD);
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

    FDCFG->viewCFG(LangOptions());

    // do a forward dataflow analysis with a worklist algorithm
    // I want to compute noexcept specification for the function by going over
    // the statements and try and catch blocks. at the end i want to have
    // noexcept false if there are any uncaught throws, otherwise it is the
    // and-combined noexcept specification of the called functions

    auto &Entry = FDCFG->getEntry();
    std::queue<const CFGBlock *> Worklist;

    for (auto &&Starts : Entry.succs()) {
      Worklist.push(Starts);
    }

    // dataflow domain for statements
    struct ThrowInfo {
      std::set<Stmt *> FunctionCallsThatCanInfluenceNoexcept;
      constexpr bool operator==(const ThrowInfo &Other) const {
        return FunctionCallsThatCanInfluenceNoexcept ==
               Other.FunctionCallsThatCanInfluenceNoexcept;
      }
    };
    std::map<const Stmt *, ThrowInfo> Throws;

    while (!Worklist.empty()) {
      const CFGBlock *Current = Worklist.front();
      Worklist.pop();

      auto IsTryCFGBlock = [](const CFGBlock *Current) {
        const Stmt *TerminatorStmt = Current->getTerminatorStmt();
        if (!TerminatorStmt)
          return false;
        return TerminatorStmt->getStmtClass() == Stmt::CXXTryStmtClass;
      };
      // dump the CFGBlock if it is a catch block
      if (IsTryCFGBlock(Current)) {
        Current->dump();
        llvm::errs() << Current->getTerminatorStmt()->getStmtClassName()
                     << "\n";
      }

      for (const CFGBlock *Succ : Current->succs()) {
        Worklist.push(Succ);
      }
    }

    EC.BodyIndex[FD] = Body;
    EC.IsInMainFileIndex[FD] = SM.isInMainFile(FD->getLocation());

    clang::ast_matchers::MatchFinder MF;
    ExceptionInfo EI;
    auto CallAction = std::make_unique<CalledFunctionInfoConsumer>(EI, SM);
    auto ThrowAction = std::make_unique<ThrownExceptionInfoConsumer>(EI, SM);
    auto CatchAction = std::make_unique<CaughtExceptionInfoConsumer>(EI, SM);
    auto TryAction = std::make_unique<TryBlockInfoConsumer>(EI, SM);
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
#endif
  }

  void handleDecl(Decl *D) {
    if (!D)
      return;

    if (auto *FD = dyn_cast<FunctionDecl>(D)) {
      handleFunction(FD);
    }

    if (const DeclContext *DC = dyn_cast<DeclContext>(D)) {
      for (Decl *SubDecl : DC->decls()) {
        handleDecl(SubDecl);
      }
    }

    while (!ExplorationWorklist.empty()) {
      FunctionDecl *FD = ExplorationWorklist.front();
      handleFunction(FD);
      ExplorationWorklist.pop();
    }
  }

  clang::ASTContext &AC;
  clang::SourceManager &SM;
  ExceptionContext &EC;
  std::set<FunctionDecl *> SeenFunctions;
  std::queue<FunctionDecl *> ExplorationWorklist;
};
