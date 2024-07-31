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
#include <queue>
#include <set>

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

class ClangExceptionScanConsumer : public clang::ASTConsumer {
public:
  ClangExceptionScanConsumer(clang::ASTContext &Context, ExceptionContext &EC)
      : AC(Context), SM(Context.getSourceManager()), EC(EC) {}

  ~ClangExceptionScanConsumer() {}

  void HandleTranslationUnit(ASTContext &Context) override {
    handleDecl(Context.getTranslationUnitDecl());
  }

private:
  void postOrderVisitCallees(CallGraphNode *Node,
                             std::set<CallGraphNode *> &SeenNodes,
                             std::vector<CallGraphNode *> &PostOrder) {
    SeenNodes.insert(Node);
    for (CallGraphNode::iterator I = Node->begin(), E = Node->end(); I != E;
         ++I) {
      CallGraphNode *Callee = *I;
      if (SeenNodes.count(Callee) == 0) {
        postOrderVisitCallees(Callee, SeenNodes, PostOrder);
      }
    }
    PostOrder.push_back(Node);
  }

  std::vector<FunctionDecl *> getAllCalleesPostorder(FunctionDecl *FD) {
    std::set<CallGraphNode *> SeenNodes;
    std::vector<FunctionDecl *> PostOrder;
    clang::CallGraph CG;
    CG.addToCallGraph(FD);
    postOrderVisitCallees(CG.getRoot(), SeenNodes, PostOrder);
  }

  void handleFunction(FunctionDecl *FD) {

    std::set<CallGraphNode *> SeenNodes;
    std::vector<CallGraphNode *> Postorder;

    for (CallGraphNode *Node : Postorder) {
      llvm::outs() << "Node: ";
      Node->print(llvm::outs());
      llvm::outs() << "\n";
    }

    return;

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
  }

  void handleDecl(Decl *D) {
    if (!D)
      return;

    if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
      handleFunction(FD);
    }

    if (const DeclContext *DC = dyn_cast<DeclContext>(D)) {
      for (Decl *SubDecl : DC->decls()) {
        handleDecl(SubDecl);
      }
    }

    while (!ExplorationWorklist.empty()) {
      const FunctionDecl *FD = ExplorationWorklist.front();
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
