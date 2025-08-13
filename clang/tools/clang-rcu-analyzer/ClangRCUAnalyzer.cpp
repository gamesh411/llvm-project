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
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
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

static llvm::cl::opt<std::string> RootFunctionOpt(
    "root-function",
    llvm::cl::desc(
        "Limit interprocedural dominator aggregation to call-sites reachable from the given function (qualified name)"),
    llvm::cl::init(""), llvm::cl::cat(RCUAnalyzerCategory));

static bool isTargetRCUName(StringRef Name) {
  return Name == "rcu_read_lock" || Name == "rcu_read_unlock" ||
         Name == "rcu_assign_pointer" || Name == "synchronize_rcu" ||
         Name == "call_rcu" || Name == "rcu_dereference";
}

struct DomInfo { SourceLocation Loc; std::string Text; bool Value; };
static std::string makeDomKey(const ASTContext &Ctx, const DomInfo &D) {
  const SourceManager &SM = Ctx.getSourceManager();
  PresumedLoc P = SM.getPresumedLoc(D.Loc);
  std::string File = P.isValid() ? std::string(P.getFilename()) : std::string();
  unsigned Line = P.isValid() ? P.getLine() : 0;
  unsigned Col = P.isValid() ? P.getColumn() : 0;
  std::string Key;
  Key.reserve(D.Text.size() + File.size() + 32);
  Key.append(File).append(":").append(std::to_string(Line)).append(":").append(std::to_string(Col))
     .append("|").append(D.Text).append("|").append(D.Value ? "T" : "F");
  return Key;
}

class RCUVisitor : public RecursiveASTVisitor<RCUVisitor> {
public:
  explicit RCUVisitor(ASTContext &Context,
                      const llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<DomInfo, 8>> *Interproc,
                      const llvm::DenseMap<const FunctionDecl *, llvm::StringMap<unsigned>> *InterprocCounts,
                      const llvm::DenseMap<const FunctionDecl *, unsigned> *InterprocSites)
      : Ctx(Context), InterprocDomByFunc(Interproc), InterprocDomCounts(InterprocCounts), InterprocCallSites(InterprocSites) {}

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

      // Append interprocedural caller-site dominators if available for this function.
      if (InterprocDomByFunc) {
        auto It = InterprocDomByFunc->find(NearestFD);
        if (It != InterprocDomByFunc->end()) {
          for (const auto &D : It->second) Dominators.push_back(D);
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
      llvm::outs() << "]";

      // Interprocedural sets: possibly_dominates (union over call-sites) and definitely_dominates (intersection)
      if (InterprocDomByFunc) {
        const FunctionDecl *DefFD = NearestFD;
        auto ItU = InterprocDomByFunc->find(DefFD);
        if (ItU != InterprocDomByFunc->end()) {
          // Stable-order union
          llvm::SmallVector<DomInfo, 16> Possibly;
          Possibly.append(ItU->second.begin(), ItU->second.end());
          std::sort(Possibly.begin(), Possibly.end(), [&](const DomInfo &A, const DomInfo &B) {
            PresumedLoc PA = SM.getPresumedLoc(A.Loc);
            PresumedLoc PB2 = SM.getPresumedLoc(B.Loc);
            std::string AFile = PA.isValid() ? std::string(PA.getFilename()) : std::string();
            std::string BFile = PB2.isValid() ? std::string(PB2.getFilename()) : std::string();
            if (AFile != BFile) return AFile < BFile;
            if ((PA.isValid() ? PA.getLine() : 0) != (PB2.isValid() ? PB2.getLine() : 0))
              return (PA.isValid() ? PA.getLine() : 0) < (PB2.isValid() ? PB2.getLine() : 0);
            return (PA.isValid() ? PA.getColumn() : 0) < (PB2.isValid() ? PB2.getColumn() : 0);
          });
          llvm::outs() << ",\"possibly_dominates\":[";
          for (size_t i = 0; i < Possibly.size(); ++i) {
            if (i) llvm::outs() << ",";
            PresumedLoc PD = SM.getPresumedLoc(Possibly[i].Loc);
            llvm::outs() << "{\"text\":\"" << Possibly[i].Text << "\",\"value\":"
                         << (Possibly[i].Value ? "true" : "false")
                         << ",\"file\":\"" << (PD.isValid() ? PD.getFilename() : "")
                         << "\",\"line\":" << (PD.isValid() ? PD.getLine() : 0)
                         << ",\"col\":" << (PD.isValid() ? PD.getColumn() : 0) << "}";
          }
          llvm::outs() << "]";

          if (InterprocDomCounts && InterprocCallSites) {
            auto ItC = InterprocDomCounts->find(DefFD);
            auto ItN = InterprocCallSites->find(DefFD);
            if (ItC != InterprocDomCounts->end() && ItN != InterprocCallSites->end() && ItN->second > 0) {
              const auto &CountMap = ItC->second;
              unsigned TotalSites = ItN->second;
              llvm::SmallVector<DomInfo, 16> Definite;
              if (TotalSites == 1) {
                // With a single call-site, union equals intersection.
                Definite.append(Possibly.begin(), Possibly.end());
              } else {
                for (const auto &D : Possibly) {
                  std::string Key = makeDomKey(Ctx, D);
                  auto Fit = CountMap.find(Key);
                  if (Fit != CountMap.end() && Fit->getValue() == TotalSites) Definite.push_back(D);
                }
              }
              std::sort(Definite.begin(), Definite.end(), [&](const DomInfo &A, const DomInfo &B) {
                PresumedLoc PA = SM.getPresumedLoc(A.Loc);
                PresumedLoc PB2 = SM.getPresumedLoc(B.Loc);
                std::string AFile = PA.isValid() ? std::string(PA.getFilename()) : std::string();
                std::string BFile = PB2.isValid() ? std::string(PB2.getFilename()) : std::string();
                if (AFile != BFile) return AFile < BFile;
                if ((PA.isValid() ? PA.getLine() : 0) != (PB2.isValid() ? PB2.getLine() : 0))
                  return (PA.isValid() ? PA.getLine() : 0) < (PB2.isValid() ? PB2.getLine() : 0);
                return (PA.isValid() ? PA.getColumn() : 0) < (PB2.isValid() ? PB2.getColumn() : 0);
              });
              llvm::outs() << ",\"definitely_dominates\":[";
              for (size_t i = 0; i < Definite.size(); ++i) {
                if (i) llvm::outs() << ",";
                PresumedLoc PD = SM.getPresumedLoc(Definite[i].Loc);
                llvm::outs() << "{\"text\":\"" << Definite[i].Text << "\",\"value\":"
                             << (Definite[i].Value ? "true" : "false")
                             << ",\"file\":\"" << (PD.isValid() ? PD.getFilename() : "")
                             << "\",\"line\":" << (PD.isValid() ? PD.getLine() : 0)
                             << ",\"col\":" << (PD.isValid() ? PD.getColumn() : 0) << "}";
              }
              llvm::outs() << "]";
            }
          }
        }
      }

      llvm::outs() << "}\n";
    }

    // Sections mode handled in translation unit processing.

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
  const llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<DomInfo, 8>> *InterprocDomByFunc;
  const llvm::DenseMap<const FunctionDecl *, llvm::StringMap<unsigned>> *InterprocDomCounts;
  const llvm::DenseMap<const FunctionDecl *, unsigned> *InterprocCallSites;
  llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<SourceLocation, 4>>
      LockStack;
  llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<size_t, 4>>
      BranchStartIdx;
  llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<std::string, 4>>
      BranchTexts;
};

// --- Conservative sections detection via dominance and post-dominance ---

class RCUPointsConsumer : public ASTConsumer {
public:
  explicit RCUPointsConsumer(ASTContext &Context) : Visitor(Context, &CallerDomByFunc, &CallerDomCountsByFunc, &CallerSiteCountByFunc) {}
  void HandleTranslationUnit(ASTContext &Context) override {
    // Precompute which functions contain RCU-related calls (intra-procedural scan)
    llvm::SmallVector<const FunctionDecl *, 32> Functions;
    for (const Decl *D : Context.getTranslationUnitDecl()->decls())
      if (const auto *FD = dyn_cast<FunctionDecl>(D))
        if (FD->doesThisDeclarationHaveABody()) Functions.push_back(FD);

    auto functionHasRCUCall = [&](const FunctionDecl *FD) {
      const Stmt *Body = FD->getBody(); if (!Body) return false;
      std::function<bool(const Stmt*)> rec = [&](const Stmt *S)->bool{
        if (!S) return false;
        if (const auto *CE = dyn_cast<CallExpr>(S)) {
          if (const FunctionDecl *Callee = CE->getDirectCallee()) {
            if (isTargetRCUName(Callee->getName())) return true;
          }
        }
        for (const Stmt *Child : S->children()) {
          if (rec(Child)) return true;
        }
        return false;
      };
      return rec(Body);
    };

    llvm::DenseSet<const FunctionDecl *> RCUFuncs;
    for (const FunctionDecl *FD : Functions) if (functionHasRCUCall(FD)) RCUFuncs.insert(FD);

    // Optionally restrict to functions reachable from a specific root function
    llvm::DenseSet<const FunctionDecl *> Allowed;
    if (!RootFunctionOpt.empty()) {
      const FunctionDecl *RootFD = nullptr;
      for (const FunctionDecl *FD : Functions) {
        SmallString<128> S; llvm::raw_svector_ostream OS(S); FD->printQualifiedName(OS);
        if (OS.str() == RootFunctionOpt) { RootFD = FD; break; }
      }
      if (RootFD) {
        // Build a naive call graph (intra-TU, direct calls only) and BFS from root
        llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<const FunctionDecl *, 8>> CG;
        for (const FunctionDecl *FD : Functions) {
          std::function<void(const Stmt*)> rec = [&](const Stmt *S){
            if (!S) return;
            if (const auto *CE = dyn_cast<CallExpr>(S)) {
              if (const FunctionDecl *Callee = CE->getDirectCallee()) CG[FD].push_back(Callee);
            }
            for (const Stmt *Ch : S->children()) rec(Ch);
          };
          if (const Stmt *B = FD->getBody()) rec(B);
        }
        llvm::SmallVector<const FunctionDecl *, 32> WL; llvm::DenseSet<const FunctionDecl *> Vis;
        WL.push_back(RootFD); Vis.insert(RootFD);
        while (!WL.empty()) {
          const FunctionDecl *F = WL.pop_back_val(); Allowed.insert(F);
          for (const FunctionDecl *C : CG[F]) if (Vis.insert(C).second) WL.push_back(C);
        }
      }
    }

    // For each function, compute dominator conditions at call-sites to RCU-containing callees
    for (const FunctionDecl *FD : Functions) {
      if (!Allowed.empty() && !Allowed.contains(FD)) continue;
      CFG::BuildOptions Opts; Opts.PruneTriviallyFalseEdges = true; Opts.setAllAlwaysAdd();
      std::unique_ptr<CFG> Cfg = CFG::buildCFG(FD, FD->getBody(), &Context, Opts);
      if (!Cfg) continue;
      CFGDomTree DT; DT.buildDominatorTree(Cfg.get());

      // Map CallExpr (call-site) to callee
      for (const CFGBlock *BB : *Cfg) {
        if (!BB) continue;
        for (const auto &Elt : *BB) {
          if (auto CS = Elt.getAs<CFGStmt>()) {
            if (const auto *CE = dyn_cast<CallExpr>(CS->getStmt())) {
              const FunctionDecl *Callee = CE->getDirectCallee();
              if (!Callee || !RCUFuncs.contains(Callee)) continue;
              if (!Allowed.empty() && !Allowed.contains(Callee)) continue;

              // Compute dominating conditions for this call-site
              const CFGBlock *CallBB = nullptr;
              for (const auto &Elt2 : *BB) {
                if (auto CS2 = Elt2.getAs<CFGStmt>()) if (CS2->getStmt() == CE) { CallBB = BB; break; }
              }
              if (!CallBB) continue;

              auto reaches = [&](const CFGBlock *Start, const CFGBlock *Goal) {
                if (!Start) return false;
                llvm::SmallVector<const CFGBlock *, 32> Stack;
                llvm::SmallPtrSet<const CFGBlock *, 32> Vis;
                Stack.push_back(Start);
                while (!Stack.empty()) {
                  const CFGBlock *B = Stack.pop_back_val();
                  if (!B || Vis.count(B)) continue;
                  Vis.insert(B);
                  if (B == Goal) return true;
                  for (auto SI = B->succ_begin(); SI != B->succ_end(); ++SI) {
                    const CFGBlock *NB = SI->getReachableBlock();
                    if (NB && !Vis.count(NB)) Stack.push_back(NB);
                  }
                }
                return false;
              };

              llvm::SmallVector<DomInfo, 8> DomSet;
              auto &DTBase = DT.getBase();
              const CFGBlock *Cur = CallBB;
              while (true) {
                auto *Node = DTBase.getNode(const_cast<CFGBlock *>(Cur));
                if (!Node) break;
                auto *IDom = Node->getIDom(); if (!IDom) break;
                const CFGBlock *DomBB = IDom->getBlock(); if (!DomBB) break;
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
                    bool value = r0;
                    std::string Text = RCUVisitor::getSourceText(Context, Cond->getSourceRange());
                    if (!Text.empty()) DomSet.push_back({Cond->getExprLoc(), std::move(Text), value});
                  }
                }
                Cur = DomBB;
              }

              // Dedup and store for callee (union)
              auto &Vec = CallerDomByFunc[Callee];
              for (auto &D : DomSet) {
                bool exists = false;
                for (const auto &E : Vec) {
                  if (E.Value == D.Value && E.Text == D.Text && E.Loc == D.Loc) { exists = true; break; }
                }
                if (!exists) Vec.push_back(std::move(D));
              }

              // Count occurrences for definitely_dominates
              auto &CountMap = CallerDomCountsByFunc[Callee];
              llvm::StringSet<> Seen;
              for (const auto &D : DomSet) {
                std::string K = makeDomKey(Context, D);
                if (Seen.insert(K).second) CountMap[K] += 1;
              }

              // Increment number of call-sites observed for this callee
              CallerSiteCountByFunc[Callee] += 1;
            }
          }
        }
      }
    }

    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
  }
private:
  llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<DomInfo, 8>> CallerDomByFunc;
  llvm::DenseMap<const FunctionDecl *, llvm::StringMap<unsigned>> CallerDomCountsByFunc;
  llvm::DenseMap<const FunctionDecl *, unsigned> CallerSiteCountByFunc;
  RCUVisitor Visitor;
};

class RCUSectionsConsumer : public ASTConsumer {
public:
  explicit RCUSectionsConsumer(ASTContext &Context) { (void)Context; }
  void HandleTranslationUnit(ASTContext &Context) override {
    const SourceManager &SM = Context.getSourceManager();
    // --- Build intra-TU call map and direct-unlock summaries (for provenance/chain) ---
    llvm::SmallVector<const FunctionDecl *, 64> AllFuncs;
    const TranslationUnitDecl *TUForSummary = Context.getTranslationUnitDecl();
    for (const Decl *D : TUForSummary->decls())
      if (const auto *FD = dyn_cast<FunctionDecl>(D))
        if (FD->doesThisDeclarationHaveABody()) AllFuncs.push_back(FD);

    struct CGCallSite { const FunctionDecl *Callee; const CallExpr *CE; };
    llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<CGCallSite, 8>> CallsFrom;
    llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<SourceLocation, 4>> DirectUnlockLocs;

    for (const FunctionDecl *FD : AllFuncs) {
      const Stmt *Body = FD->getBody();
      if (!Body) continue;
      std::function<void(const Stmt*)> rec = [&](const Stmt *S){
        if (!S) return;
        if (const auto *CE = dyn_cast<CallExpr>(S)) {
          if (const FunctionDecl *Callee = CE->getDirectCallee()) {
            CallsFrom[FD].push_back({Callee, CE});
            if (Callee->getName() == "rcu_read_unlock") {
              DirectUnlockLocs[FD].push_back(CE->getExprLoc());
            }
          }
        }
        for (const Stmt *Ch : S->children()) rec(Ch);
      };
      rec(Body);
    }

    // Compute a transitive "does unlock" summary and store one witness edge per function.
    llvm::DenseMap<const FunctionDecl *, bool> DoesUnlock;
    llvm::DenseMap<const FunctionDecl *, std::pair<const FunctionDecl *, const CallExpr *>> UnlockVia;
    for (const FunctionDecl *FD : AllFuncs)
      DoesUnlock[FD] = !DirectUnlockLocs[FD].empty();
    bool Changed = true;
    while (Changed) {
      Changed = false;
      for (const FunctionDecl *FD : AllFuncs) {
        if (DoesUnlock[FD]) continue;
        auto It = CallsFrom.find(FD);
        if (It == CallsFrom.end()) continue;
        for (const auto &CS : It->second) {
          if (DoesUnlock.lookup(CS.Callee)) {
            DoesUnlock[FD] = true;
            if (!DirectUnlockLocs[FD].size() && !UnlockVia.count(FD))
              UnlockVia[FD] = {CS.Callee, CS.CE};
            Changed = true;
            break;
          }
        }
      }
    }
    auto processFunction = [&](const FunctionDecl *FD) {
      if (!FD->doesThisDeclarationHaveABody()) return;
      if (!SM.isInMainFile(FD->getLocation())) return;

      auto printSection = [&](SourceLocation Begin, SourceLocation End, const char *Kind) {
        PresumedLoc PB = SM.getPresumedLoc(Begin);
        PresumedLoc PE = SM.getPresumedLoc(End);
        SmallString<128> S; llvm::raw_svector_ostream OS(S);
        FD->printQualifiedName(OS); std::string Fn = std::string(OS.str());
        llvm::outs() << "{\"type\":\"read_section\",\"kind\":\"" << Kind
                     << "\",\"function\":\"" << Fn
                     << "\",\"begin_file\":\"" << (PB.isValid() ? PB.getFilename() : "")
                     << "\",\"begin_line\":" << (PB.isValid() ? PB.getLine() : 0)
                     << ",\"begin_col\":" << (PB.isValid() ? PB.getColumn() : 0)
                     << ",\"end_file\":\"" << (PE.isValid() ? PE.getFilename() : "")
                     << "\",\"end_line\":" << (PE.isValid() ? PE.getLine() : 0)
                     << ",\"end_col\":" << (PE.isValid() ? PE.getColumn() : 0)
                     << "}\n";
      };

      CFG::BuildOptions Opts; Opts.PruneTriviallyFalseEdges = true; Opts.setAllAlwaysAdd();
      std::unique_ptr<CFG> Cfg = CFG::buildCFG(FD, FD->getBody(), &Context, Opts);
      if (!Cfg) return;
      CFGDomTree Dom; Dom.buildDominatorTree(Cfg.get());
      CFGPostDomTree PostDom; PostDom.buildDominatorTree(Cfg.get());

      struct CallSite { const CFGBlock *BB; SourceLocation Loc; const CallExpr *CE; };
      llvm::SmallVector<CallSite, 16> Locks, Unlocks;
      for (const CFGBlock *BB : *Cfg) {
        if (!BB) continue;
        for (const auto &Elt : *BB) {
          if (auto CS = Elt.getAs<CFGStmt>()) {
            if (const auto *CE = dyn_cast<CallExpr>(CS->getStmt())) {
              if (const FunctionDecl *Callee = CE->getDirectCallee()) {
                StringRef N = Callee->getName();
                if (N == "rcu_read_lock") Locks.push_back({BB, CE->getExprLoc(), CE});
                else if (N == "rcu_read_unlock") Unlocks.push_back({BB, CE->getExprLoc(), CE});
              }
            }
          }
        }
      }

      // First handle same-block linear sections via intrablock stack pairing.
      llvm::SmallPtrSet<const CallExpr *, 32> UsedLock, UsedUnlock;
      for (const CFGBlock *BB : *Cfg) {
        if (!BB) continue;
        llvm::SmallVector<const CallExpr *, 8> Stack;
        struct Pair { const CallExpr *Begin; const CallExpr *End; };
        llvm::SmallVector<Pair, 8> Pairs;
        for (const auto &Elt : *BB) {
          if (auto CS = Elt.getAs<CFGStmt>()) {
            if (const auto *CE = dyn_cast<CallExpr>(CS->getStmt())) {
              const FunctionDecl *Callee = CE->getDirectCallee();
              if (!Callee) continue;
              StringRef N = Callee->getName();
              if (N == "rcu_read_lock") {
                Stack.push_back(CE);
              } else if (N == "rcu_read_unlock") {
                if (!Stack.empty()) {
                  const CallExpr *BeginCE = Stack.pop_back_val();
                  UsedLock.insert(BeginCE);
                  UsedUnlock.insert(CE);
                  Pairs.push_back({BeginCE, CE});
                }
              }
            }
          }
        }
        // Print pairs sorted by begin location to ensure outer sections appear before inner ones.
        std::sort(Pairs.begin(), Pairs.end(), [&](const Pair &A, const Pair &B){
          PresumedLoc PA = SM.getPresumedLoc(A.Begin->getExprLoc());
          PresumedLoc PB = SM.getPresumedLoc(B.Begin->getExprLoc());
          std::string AFile = PA.isValid() ? std::string(PA.getFilename()) : std::string();
          std::string BFile = PB.isValid() ? std::string(PB.getFilename()) : std::string();
          if (AFile != BFile) return AFile < BFile;
          if ((PA.isValid() ? PA.getLine() : 0) != (PB.isValid() ? PB.getLine() : 0))
            return (PA.isValid() ? PA.getLine() : 0) < (PB.isValid() ? PB.getLine() : 0);
          return (PA.isValid() ? PA.getColumn() : 0) < (PB.isValid() ? PB.getColumn() : 0);
        });
        for (const auto &P : Pairs) {
          printSection(P.Begin->getExprLoc(), P.End->getExprLoc(), "linear");
        }
      }

      for (const auto &L : Locks) {
        for (const auto &U : Unlocks) {
          // Skip pairs already emitted via intrablock linear pairing.
          if (UsedLock.count(L.CE) || UsedUnlock.count(U.CE)) continue;
          if (L.BB == U.BB) continue;
          const bool DomOK = Dom.dominates(const_cast<CFGBlock *>(L.BB), const_cast<CFGBlock *>(U.BB));
          const bool PostOK = PostDom.dominates(const_cast<CFGBlock *>(U.BB), const_cast<CFGBlock *>(L.BB));
          if (DomOK && PostOK) {
            printSection(L.Loc, U.Loc, "branched");
          }
        }
      }

      // Interprocedural: if this function calls a callee summarized to unlock (transitively), emit an interprocedural section.
      if (!Locks.empty()) {
        for (const CFGBlock *BB : *Cfg) {
          if (!BB) continue;
          for (const auto &Elt : *BB) {
            if (auto CS = Elt.getAs<CFGStmt>()) {
              if (const auto *CE = dyn_cast<CallExpr>(CS->getStmt())) {
                if (const FunctionDecl *Callee = CE->getDirectCallee()) {
                  if (DoesUnlock.lookup(Callee)) {
                    // Pick first lock as begin, and use callee unlock loc as end (approx: use call loc).
                    SourceLocation Begin = Locks.front().Loc;
                    SourceLocation End = CE->getExprLoc();
                    // Confidence: definite if single call-site; probable otherwise
                    const char *Conf = "probable";
                    unsigned CallsToCallee = 0;
                    for (const auto &LBB : *Cfg) if (LBB)
                      for (const auto &E2 : *LBB) if (auto CS2 = E2.getAs<CFGStmt>())
                        if (const auto *CE2 = dyn_cast<CallExpr>(CS2->getStmt()))
                          if (CE2->getDirectCallee() == Callee) ++CallsToCallee;
                    if (CallsToCallee == 1) Conf = "definite";
                    // Build provenance and call_chain
                    // Build call_chain frames starting from this call-site, then following UnlockVia until direct unlock.
                    struct Frame { const FunctionDecl *F; SourceLocation Loc; bool IsUnlock; };
                    llvm::SmallVector<Frame, 8> Chain;
                    Chain.push_back({FD, CE->getExprLoc(), false});
                    const FunctionDecl *Cur = Callee;
                    SourceLocation FinalUnlockLoc;
                    const FunctionDecl *FinalUnlockFunc = nullptr;
                    // Limit depth to avoid pathological recursion; practical cases are shallow.
                    unsigned Depth = 0;
                    while (Cur && Depth++ < 16) {
                      if (!DirectUnlockLocs[Cur].empty()) {
                        FinalUnlockLoc = DirectUnlockLocs[Cur].front();
                        FinalUnlockFunc = Cur;
                        Chain.push_back({Cur, FinalUnlockLoc, true});
                        break;
                      }
                      auto ItVia = UnlockVia.find(Cur);
                      if (ItVia == UnlockVia.end()) break;
                      const FunctionDecl *Next = ItVia->second.first;
                      const CallExpr *InnerCE = ItVia->second.second;
                      Chain.push_back({Cur, InnerCE ? InnerCE->getExprLoc() : Cur->getLocation(), false});
                      Cur = Next;
                    }
                    // Emit
                    SmallString<128> S; llvm::raw_svector_ostream OS(S);
                    FD->printQualifiedName(OS); std::string Fn = std::string(OS.str());
                    PresumedLoc PB = SM.getPresumedLoc(Begin);
                    PresumedLoc PE = SM.getPresumedLoc(End);
                    llvm::outs() << "{\"type\":\"read_section\",\"kind\":\"interprocedural\",\"confidence\":\"" << Conf
                                 << "\",\"function\":\"" << Fn
                                 << "\",\"begin_file\":\"" << (PB.isValid() ? PB.getFilename() : "")
                                 << "\",\"begin_line\":" << (PB.isValid() ? PB.getLine() : 0)
                                 << ",\"begin_col\":" << (PB.isValid() ? PB.getColumn() : 0)
                                 << ",\"end_file\":\"" << (PE.isValid() ? PE.getFilename() : "")
                                 << "\",\"end_line\":" << (PE.isValid() ? PE.getLine() : 0)
                                 << ",\"end_col\":" << (PE.isValid() ? PE.getColumn() : 0);
                    // provenance
                    if (FinalUnlockFunc) {
                      PresumedLoc PUL = SM.getPresumedLoc(FinalUnlockLoc);
                      llvm::outs() << ",\"provenance\":{\"closed_by\":\"" << FinalUnlockFunc->getName()
                                   << "\",\"file\":\"" << (PUL.isValid() ? PUL.getFilename() : "")
                                   << "\",\"line\":" << (PUL.isValid() ? PUL.getLine() : 0)
                                   << ",\"col\":" << (PUL.isValid() ? PUL.getColumn() : 0) << "}";
                    }
                    // call_chain
                    if (!Chain.empty()) {
                      llvm::outs() << ",\"call_chain\":[";
                      for (size_t idx = 0; idx < Chain.size(); ++idx) {
                        if (idx) llvm::outs() << ",";
                        PresumedLoc PC = SM.getPresumedLoc(Chain[idx].Loc);
                        llvm::outs() << "{\"function\":\"" << Chain[idx].F->getName()
                                     << "\",\"file\":\"" << (PC.isValid() ? PC.getFilename() : "")
                                     << "\",\"line\":" << (PC.isValid() ? PC.getLine() : 0)
                                     << ",\"col\":" << (PC.isValid() ? PC.getColumn() : 0) << "}";
                      }
                      llvm::outs() << "]";
                    }
                    llvm::outs() << "}\n";
                  }
                }
              }
            }
          }
        }
      }
    };

    const TranslationUnitDecl *TU = Context.getTranslationUnitDecl();
    for (const Decl *D : TU->decls()) if (const auto *FD = dyn_cast<FunctionDecl>(D)) processFunction(FD);
  }
private:
};

class RCUAction : public ASTFrontendAction {
public:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef) override {
    if (ModeOpt == AnalysisMode::Points) {
      return std::make_unique<RCUPointsConsumer>(CI.getASTContext());
    }
    return std::make_unique<RCUSectionsConsumer>(CI.getASTContext());
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


