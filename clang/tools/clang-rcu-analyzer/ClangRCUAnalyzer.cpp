//===- ClangRCUAnalyzer.cpp ----------------------------------------------===//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Lex/Lexer.h"
#include "clang/Analysis/FlowSensitive/DataflowAnalysis.h"
#include "clang/Analysis/FlowSensitive/AdornedCFG.h"
#include "clang/Analysis/FlowSensitive/WatchedLiteralsSolver.h"
#include "clang/Analysis/FlowSensitive/TypeErasedDataflowAnalysis.h"
#include "clang/Analysis/FlowSensitive/DataflowEnvironment.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/Analyses/Dominators.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Signals.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include <string>

using namespace clang;
using namespace clang::tooling;

static llvm::cl::OptionCategory RCUAnalyzerCategory("clang-rcu-analyzer options");

namespace cdf = clang::dataflow;

namespace {

enum class AnalysisMode { Points, Sections };

static llvm::cl::opt<AnalysisMode> ModeOpt(
    "mode", llvm::cl::desc("Analysis mode"),
    llvm::cl::values(clEnumValN(AnalysisMode::Points, "points",
                          "Print RCU-related calls with exact locations"),
               clEnumValN(AnalysisMode::Sections, "sections",
                          "Detect read-side critical sections and emit source "
                          "ranges")),
    llvm::cl::init(AnalysisMode::Points), llvm::cl::cat(RCUAnalyzerCategory));

static bool isTargetRCUName(StringRef Name) {
  return Name == "rcu_read_lock" || Name == "rcu_read_unlock" ||
         Name == "rcu_assign_pointer" || Name == "synchronize_rcu" ||
         Name == "call_rcu" || Name == "rcu_dereference";
}

class RCUVisitor : public RecursiveASTVisitor<RCUVisitor> {
public:
  explicit RCUVisitor(ASTContext &Context) : Ctx(Context) {}

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return true;

    StringRef CalleeName = FD->getName();
    if (!isTargetRCUName(CalleeName))
      return true;

    // Ignore calls that are not located in the main file.
    const SourceManager &SM = Ctx.getSourceManager();
    SourceLocation Loc = CE->getExprLoc();
    if (!SM.isInMainFile(Loc))
      return true;

    // Find the nearest enclosing FunctionDecl by walking parents.
    const FunctionDecl *NearestFD = getEnclosingFunction(CE);
    std::string FuncName;
    if (NearestFD) {
      SmallString<128> S;
      llvm::raw_svector_ostream OS(S);
      NearestFD->printQualifiedName(OS);
      FuncName = std::string(OS.str());
    } else {
      FuncName = "<global>";
    }

    PresumedLoc PLoc = SM.getPresumedLoc(Loc);

    if (ModeOpt == AnalysisMode::Points) {
      // Minimal computation of dominating control conditions for this call.
      struct DomInfo { SourceLocation Loc; std::string Text; bool Value; };
      llvm::SmallVector<DomInfo, 16> Dominators;

      if (NearestFD && NearestFD->doesThisDeclarationHaveABody()) {
        const FunctionDecl *DefFD = NearestFD;
        (void)NearestFD->hasBody(DefFD);
        // Build a plain CFG that works for C as well.
        CFG::BuildOptions Opts;
        Opts.PruneTriviallyFalseEdges = true;
        Opts.setAllAlwaysAdd();
        std::unique_ptr<CFG> Cfg = CFG::buildCFG(DefFD, DefFD->getBody(), &Ctx, Opts);
        if (Cfg) {
          CFGDomTree DT;
          DT.buildDominatorTree(Cfg.get());

          // Map call to its CFG block by scanning elements.
          const CFGBlock *TargetBB = nullptr;
          for (const CFGBlock *BB : *Cfg) {
            if (!BB) continue;
            for (const auto &Elt : *BB) {
              if (auto CS = Elt.getAs<CFGStmt>()) {
                if (CS->getStmt() == CE) { TargetBB = BB; break; }
              }
            }
            if (TargetBB) break;
          }

          if (TargetBB) {
            auto reaches = [&](const CFGBlock *Start, const CFGBlock *Goal) {
              if (!Start) return false;
              llvm::SmallVector<const CFGBlock *, 32> Stack;
              llvm::SmallPtrSet<const CFGBlock *, 32> Visited;
              Stack.push_back(Start);
              while (!Stack.empty()) {
                const CFGBlock *B = Stack.pop_back_val();
                if (!B || Visited.count(B)) continue;
                Visited.insert(B);
                if (B == Goal) return true;
                for (auto SI = B->succ_begin(); SI != B->succ_end(); ++SI) {
                  const CFGBlock *NB = SI->getReachableBlock();
                  if (NB && !Visited.count(NB)) Stack.push_back(NB);
                }
              }
              return false;
            };

            auto &DTBase = DT.getBase();
            const CFGBlock *Cur = TargetBB;
            while (true) {
              auto *Node = DTBase.getNode(const_cast<CFGBlock *>(Cur));
              if (!Node) break;
              auto *IDom = Node->getIDom();
              if (!IDom) break; // reached entry
              const CFGBlock *DomBB = IDom->getBlock();
              if (!DomBB) break;
              const Stmt *Term = DomBB->getTerminatorStmt();
              const Expr *Cond = nullptr;
              if (const auto *IS = dyn_cast_or_null<IfStmt>(Term)) Cond = IS->getCond();
              else if (const auto *WS = dyn_cast_or_null<WhileStmt>(Term)) Cond = WS->getCond();
              else if (const auto *FS = dyn_cast_or_null<ForStmt>(Term)) Cond = FS->getCond();
              else if (const auto *DS = dyn_cast_or_null<DoStmt>(Term)) Cond = DS->getCond();
              else if (const auto *CO = dyn_cast_or_null<ConditionalOperator>(Term)) Cond = CO->getCond();
              else if (const auto *SS = dyn_cast_or_null<SwitchStmt>(Term)) Cond = SS->getCond();
              if (Cond) {
                const CFGBlock *Succ0 = (DomBB->succ_size() > 0) ? DomBB->succ_begin()->getReachableBlock() : nullptr;
                const CFGBlock *Succ1 = (DomBB->succ_size() > 1) ? (DomBB->succ_begin() + 1)->getReachableBlock() : nullptr;
                bool r0 = reaches(Succ0, Cur);
                bool r1 = reaches(Succ1, Cur);
                if (r0 != r1) {
                  bool value = r0; // successor 0 corresponds to 'true'
                  std::string Text = getSourceText(Ctx, Cond->getSourceRange());
                  if (!Text.empty()) Dominators.push_back({Cond->getExprLoc(), std::move(Text), value});
                }
              }
              Cur = DomBB;
            }
          }
        }
      }

      // Stable ordering by presumed location
      std::sort(Dominators.begin(), Dominators.end(), [&](const DomInfo &A, const DomInfo &B) {
        PresumedLoc PA = SM.getPresumedLoc(A.Loc);
        PresumedLoc PB2 = SM.getPresumedLoc(B.Loc);
        std::string AFile = PA.isValid() ? std::string(PA.getFilename()) : std::string();
        std::string BFile = PB2.isValid() ? std::string(PB2.getFilename()) : std::string();
        if (AFile != BFile) return AFile < BFile;
        if ((PA.isValid() ? PA.getLine() : 0) != (PB2.isValid() ? PB2.getLine() : 0))
          return (PA.isValid() ? PA.getLine() : 0) < (PB2.isValid() ? PB2.getLine() : 0);
        return (PA.isValid() ? PA.getColumn() : 0) < (PB2.isValid() ? PB2.getColumn() : 0);
      });

      // Emit JSON
      llvm::outs() << "{\"type\":\"call\",\"name\":\"" << CalleeName
                   << "\",\"function\":\"" << FuncName
                   << "\",\"file\":\"" << (PLoc.isValid() ? PLoc.getFilename() : "")
                   << "\",\"line\":" << (PLoc.isValid() ? PLoc.getLine() : 0)
                   << ",\"col\":" << (PLoc.isValid() ? PLoc.getColumn() : 0)
                   << ",\"dominators\":[";
      for (size_t i = 0; i < Dominators.size(); ++i) {
        if (i) llvm::outs() << ",";
        PresumedLoc PD = SM.getPresumedLoc(Dominators[i].Loc);
        llvm::outs() << "{\"text\":\"" << Dominators[i].Text << "\",\"value\":"
                     << (Dominators[i].Value ? "true" : "false")
                     << ",\"file\":\"" << (PD.isValid() ? PD.getFilename() : "")
                     << "\",\"line\":" << (PD.isValid() ? PD.getLine() : 0)
                     << ",\"col\":" << (PD.isValid() ? PD.getColumn() : 0) << "}";
      }
      llvm::outs() << "]}\n";
    }

    // Minimal read-section grouping for same-function linear sections:
    if (ModeOpt == AnalysisMode::Sections && NearestFD) {
      if (CalleeName == "rcu_read_lock") {
        LockStack[NearestFD].push_back(Loc);
        BranchStartIdx[NearestFD].push_back(BranchTexts[NearestFD].size());
      } else if (CalleeName == "rcu_read_unlock") {
        auto It = LockStack.find(NearestFD);
        if (It != LockStack.end() && !It->second.empty()) {
          SourceLocation BeginLoc = It->second.pop_back_val();
          PresumedLoc PBegin = SM.getPresumedLoc(BeginLoc);
          PresumedLoc PEnd = PLoc;

          SmallString<128> S;
          llvm::raw_svector_ostream OS(S);
          NearestFD->printQualifiedName(OS);
          std::string Fn = std::string(OS.str());

          // Gather branch conditions recorded since this lock.
          SmallVector<std::string, 4> Conditions;
          auto &StartIdxStack = BranchStartIdx[NearestFD];
          size_t StartIdx = 0;
          if (!StartIdxStack.empty()) {
            StartIdx = StartIdxStack.pop_back_val();
          }
          auto &BT = BranchTexts[NearestFD];
          if (StartIdx < BT.size()) {
            for (size_t i = StartIdx; i < BT.size(); ++i)
              Conditions.push_back(BT[i]);
            BT.resize(StartIdx);
          }

          const char *Kind = Conditions.empty() ? "linear" : "branched";

          llvm::outs() << "{\"type\":\"read_section\",\"kind\":\"" << Kind
                       << "\",\"function\":\"" << Fn
                       << "\",\"begin_file\":\""
                       << (PBegin.isValid() ? PBegin.getFilename() : "")
                       << "\",\"begin_line\":"
                       << (PBegin.isValid() ? PBegin.getLine() : 0)
                       << ",\"begin_col\":"
                       << (PBegin.isValid() ? PBegin.getColumn() : 0)
                       << ",\"end_file\":\""
                       << (PEnd.isValid() ? PEnd.getFilename() : "")
                       << "\",\"end_line\":"
                       << (PEnd.isValid() ? PEnd.getLine() : 0)
                       << ",\"end_col\":"
                       << (PEnd.isValid() ? PEnd.getColumn() : 0);
          if (!Conditions.empty()) {
            llvm::outs() << ",\"conditions\":[";
            for (size_t i = 0; i < Conditions.size(); ++i) {
              if (i)
                llvm::outs() << ",";
              llvm::outs() << "\"" << Conditions[i] << "\"";
            }
            llvm::outs() << "]";
          }
          llvm::outs() << "}\n";
        }
      }
    }

    return true;
  }

public:
  static std::string getSourceText(const ASTContext &Ctx,
                                   SourceRange Range) {
    const SourceManager &SM = Ctx.getSourceManager();
    LangOptions LO = Ctx.getLangOpts();
    CharSourceRange CR = CharSourceRange::getTokenRange(Range);
    return std::string(Lexer::getSourceText(CR, SM, LO));
  }

  void recordBranchCondition(const Stmt *S, const Expr *Cond) {
    if (!Cond)
      return;
    const SourceManager &SM = Ctx.getSourceManager();
    SourceLocation Loc = S->getBeginLoc();
    if (!SM.isInMainFile(Loc))
      return;
    const FunctionDecl *FD = getEnclosingFunction(S);
    if (!FD)
      return;
    auto It = LockStack.find(FD);
    if (It == LockStack.end() || It->second.empty())
      return; // no active lock
    std::string Text = getSourceText(Ctx, Cond->getSourceRange());
    if (!Text.empty())
      BranchTexts[FD].push_back(Text);
  }

  bool VisitIfStmt(IfStmt *IS) {
    recordBranchCondition(IS, IS->getCond());
    return true;
  }
  bool VisitWhileStmt(WhileStmt *WS) {
    recordBranchCondition(WS, WS->getCond());
    return true;
  }
  bool VisitForStmt(ForStmt *FS) {
    recordBranchCondition(FS, FS->getCond());
    return true;
  }
  bool VisitConditionalOperator(ConditionalOperator *CO) {
    recordBranchCondition(CO, CO->getCond());
    return true;
  }

  const FunctionDecl *getEnclosingFunction(const Stmt *S) {
    const FunctionDecl *NearestFD = nullptr;
    DynTypedNode Node = DynTypedNode::create(*S);
    while (true) {
      auto Parents = Ctx.getParents(Node);
      if (Parents.empty())
        break;
      Node = Parents[0];
      if (const auto *FDp = Node.get<FunctionDecl>()) {
        NearestFD = FDp;
        break;
      }
    }
    return NearestFD;
  }

  ASTContext &Ctx;
  llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<SourceLocation, 4>>
      LockStack;
  llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<size_t, 4>>
      BranchStartIdx;
  llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<std::string, 4>>
      BranchTexts;
};

// --- Flow-sensitive sections detection (uses dataflow framework) ---

struct RCUState {
  int lockDepth = 0;
  // Join: keep the maximum depth observed to approximate being inside.
  cdf::LatticeJoinEffect join(const RCUState &Other) {
    int Old = lockDepth;
    lockDepth = std::max(lockDepth, Other.lockDepth);
    return lockDepth == Old ? cdf::LatticeJoinEffect::Unchanged
                            : cdf::LatticeJoinEffect::Changed;
  }
  bool operator==(const RCUState &O) const { return lockDepth == O.lockDepth; }
};

class RCUSectionsAnalysis : public cdf::DataflowAnalysis<RCUSectionsAnalysis, RCUState> {
public:
  explicit RCUSectionsAnalysis(ASTContext &Ctx) : DataflowAnalysis(Ctx) {}
  RCUState initialElement() { return {}; }

  void transfer(const CFGElement &Elt, RCUState &State, cdf::Environment &) {
    if (auto StmtElt = Elt.getAs<CFGStmt>()) {
      const Stmt *S = StmtElt->getStmt();
      if (const auto *CE = dyn_cast<CallExpr>(S)) {
        if (const FunctionDecl *FD = CE->getDirectCallee()) {
          StringRef Name = FD->getName();
          if (Name == "rcu_read_lock") {
            State.lockDepth = std::min(State.lockDepth + 1, 1024);
          } else if (Name == "rcu_read_unlock") {
            State.lockDepth = std::max(State.lockDepth - 1, 0);
          }
        }
      }
    }
  }
};

class RCUConsumer : public ASTConsumer {
public:
  explicit RCUConsumer(ASTContext &Context) : Visitor(Context) {}
  void HandleTranslationUnit(ASTContext &Context) override {
    if (ModeOpt == AnalysisMode::Points) {
      // Use the existing visitor for points mode
      Visitor.TraverseDecl(Context.getTranslationUnitDecl());
      return;
    }

    const SourceManager &SM = Context.getSourceManager();
    // Sections mode below.

    // Sections mode: run dataflow per function in main file.
    
    auto processFunction = [&](const FunctionDecl *FD) {
      if (!FD->doesThisDeclarationHaveABody())
        return;
      if (!SM.isInMainFile(FD->getLocation()))
        return;

      llvm::SmallVector<std::pair<SourceLocation, SourceLocation>, 8> SectionsFound;

      struct ConditionInfo {
        SourceLocation Loc;
        std::string Text;
      };

      auto printSection = [&](SourceLocation Begin, SourceLocation End, ArrayRef<ConditionInfo> Conds) {
        PresumedLoc PB = SM.getPresumedLoc(Begin);
        PresumedLoc PE = SM.getPresumedLoc(End);
        SmallString<128> S;
        llvm::raw_svector_ostream OS(S);
        FD->printQualifiedName(OS);
        std::string Fn = std::string(OS.str());
        const char *Kind = Conds.empty() ? "linear" : "branched";
        llvm::outs() << "{\"type\":\"read_section\",\"kind\":\"" << Kind
                     << "\",\"function\":\"" << Fn
                     << "\",\"begin_file\":\""
                     << (PB.isValid() ? PB.getFilename() : "")
                     << "\",\"begin_line\":"
                     << (PB.isValid() ? PB.getLine() : 0)
                     << ",\"begin_col\":"
                     << (PB.isValid() ? PB.getColumn() : 0)
                     << ",\"end_file\":\""
                     << (PE.isValid() ? PE.getFilename() : "")
                     << "\",\"end_line\":"
                     << (PE.isValid() ? PE.getLine() : 0)
                     << ",\"end_col\":"
                     << (PE.isValid() ? PE.getColumn() : 0);
        if (!Conds.empty()) {
          llvm::outs() << ",\"conditions\":[";
          for (size_t i = 0; i < Conds.size(); ++i) {
            if (i)
              llvm::outs() << ",";
            PresumedLoc PC = SM.getPresumedLoc(Conds[i].Loc);
            llvm::outs() << "{\"text\":\"" << Conds[i].Text << "\",\"file\":\""
                         << (PC.isValid() ? PC.getFilename() : "")
                         << "\",\"line\":" << (PC.isValid() ? PC.getLine() : 0)
                         << ",\"col\":" << (PC.isValid() ? PC.getColumn() : 0) << "}";
          }
          llvm::outs() << "]";
        }
        llvm::outs() << "}\n";
      };

      // Build ACFG and analysis context.
      auto ACFGExp = cdf::AdornedCFG::build(*FD);
      if (!ACFGExp) {
        consumeError(ACFGExp.takeError());
        return;
      }
      cdf::AdornedCFG &ACFG = *ACFGExp;
      auto Solver = std::make_unique<cdf::WatchedLiteralsSolver>(cdf::kDefaultMaxSATIterations);
      cdf::DataflowAnalysisContext DFContext2(*Solver);
      cdf::Environment InitEnv(DFContext2, *FD);
      RCUSectionsAnalysis Analysis(Context);

      // Collect section pairs via a simple AST walk (function-local, linear pairing).
      std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
        if (!S) return;
        if (const auto *CE = dyn_cast<CallExpr>(S)) {
          if (const FunctionDecl *Callee = CE->getDirectCallee()) {
            StringRef Name = Callee->getName();
            static llvm::SmallVector<SourceLocation, 8> AstLockStack;
            if (Name == "rcu_read_lock") {
              AstLockStack.push_back(CE->getExprLoc());
            } else if (Name == "rcu_read_unlock") {
              if (!AstLockStack.empty()) {
                SourceLocation BeginLoc = AstLockStack.back();
                AstLockStack.pop_back();
                SectionsFound.emplace_back(BeginLoc, CE->getExprLoc());
              }
            }
          }
        }
        for (const Stmt *Child : S->children()) Walk(Child);
      };
      Walk(FD->getBody());

      cdf::CFGEltCallbacks<RCUSectionsAnalysis> Cbs{};
      Cbs.After = [&](const CFGElement &, const cdf::DataflowAnalysisState<RCUState> &) {};

      if (auto States = cdf::runDataflowAnalysis(ACFG, Analysis, InitEnv, Cbs)) {
        // Collect branch conditions from block terminators where inside-section state holds.
        llvm::SmallVector<ConditionInfo, 16> Conds;
        auto addCond = [&](const Expr *E) {
          if (!E) return;
          std::string Text = RCUVisitor::getSourceText(Context, E->getSourceRange());
          if (Text.empty()) return;
          SourceLocation L = E->getExprLoc();
          // Deduplicate by text and presumed location
          PresumedLoc Pnew = SM.getPresumedLoc(L);
          for (const auto &CI : Conds) {
            PresumedLoc Pold = SM.getPresumedLoc(CI.Loc);
            if (CI.Text == Text && ((Pnew.isValid() && Pold.isValid() &&
                                     std::string(Pnew.getFilename()) == std::string(Pold.getFilename()) &&
                                     Pnew.getLine() == Pold.getLine() && Pnew.getColumn() == Pold.getColumn()) ||
                                    (!Pnew.isValid() && !Pold.isValid()))) {
              return;
            }
          }
          Conds.push_back({L, std::move(Text)});
        };
        const CFG &Cfg = ACFG.getCFG();
        for (const CFGBlock *B : Cfg) {
          if (!B) continue;
          unsigned ID = B->getBlockID();
          if (ID >= States->size()) continue;
          const auto &OptState = (*States)[ID];
          if (!OptState) continue;
          const RCUState &St = OptState->Lattice;
          if (St.lockDepth <= 0) continue;
          if (const Stmt *Term = B->getTerminatorStmt()) {
            if (const auto *IS = dyn_cast<IfStmt>(Term)) addCond(IS->getCond());
            else if (const auto *WS = dyn_cast<WhileStmt>(Term)) addCond(WS->getCond());
            else if (const auto *FS = dyn_cast<ForStmt>(Term)) addCond(FS->getCond());
            else if (const auto *DS = dyn_cast<DoStmt>(Term)) addCond(DS->getCond());
            else if (const auto *CO = dyn_cast<ConditionalOperator>(Term)) addCond(CO->getCond());
            else if (const auto *SS = dyn_cast<SwitchStmt>(Term)) addCond(SS->getCond());
          }
        }
        // Sort by presumed source location (file, line, col).
        std::sort(Conds.begin(), Conds.end(), [&](const ConditionInfo &A, const ConditionInfo &B) {
          PresumedLoc PA = SM.getPresumedLoc(A.Loc);
          PresumedLoc PB2 = SM.getPresumedLoc(B.Loc);
          std::string AFile = PA.isValid() ? std::string(PA.getFilename()) : std::string();
          std::string BFile = PB2.isValid() ? std::string(PB2.getFilename()) : std::string();
          if (AFile != BFile) return AFile < BFile;
          if ((PA.isValid() ? PA.getLine() : 0) != (PB2.isValid() ? PB2.getLine() : 0))
            return (PA.isValid() ? PA.getLine() : 0) < (PB2.isValid() ? PB2.getLine() : 0);
          return (PA.isValid() ? PA.getColumn() : 0) < (PB2.isValid() ? PB2.getColumn() : 0);
        });
        // Emit all found sections with collected conditions.
        for (const auto &Sec : SectionsFound) {
          printSection(Sec.first, Sec.second, Conds);
        }
      } else {
        consumeError(States.takeError());
      }
    };

    const TranslationUnitDecl *TU = Context.getTranslationUnitDecl();
    for (const Decl *D : TU->decls()) {
      if (const auto *FD = dyn_cast<FunctionDecl>(D))
        processFunction(FD);
    }
  }

private:
  RCUVisitor Visitor;
};

class RCUAction : public ASTFrontendAction {
public:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef) override {
    return std::make_unique<RCUConsumer>(CI.getASTContext());
  }
};

} // namespace

int main(int argc, const char **argv) {
  llvm::sys::PrintStackTraceOnErrorSignal(argv[0], false);
  llvm::PrettyStackTraceProgram X(argc, argv);

  auto ExpectedParser = CommonOptionsParser::create(argc, argv,
                                                    RCUAnalyzerCategory);
  if (!ExpectedParser) {
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }
  CommonOptionsParser &OptionsParser = ExpectedParser.get();

  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());
  return Tool.run(newFrontendActionFactory<RCUAction>().get());
}


