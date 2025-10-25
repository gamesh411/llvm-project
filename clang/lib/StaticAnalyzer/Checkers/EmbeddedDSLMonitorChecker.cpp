#include "clang/AST/Stmt.h"
//===-- EmbeddedDSLMonitorChecker.cpp --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Dynamic Embedded DSL for Temporal Logic-based Static Analysis
//
// This implementation provides a reusable DSL framework where:
// 1. Checker callbacks provide generic events (preCall, postCall, deadSymbols)
// 2. DSL formulas define monitor automatons for temporal logic properties
// 3. ASTMatchers and symbol tracking are handled generically
// 4. Properties can be declaratively specified without checker-specific code
//
// Pure Linear Temporal Logic Formula for malloc/free:
//   G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → G ¬free(x) ) )
//
// English: "It is always true that: if a malloc call succeeds, then that memory
// must eventually be freed, and once it is freed, it can never be freed again
// in any subsequent step."
//
// The DSL framework supports:
//   - Generic event handling (preCall, postCall, deadSymbols)
//   - ASTMatchers integration for pattern matching
//   - String-based GDM for symbol tracking
//   - Declarative property specification
//   - Reusable monitor automatons
//===----------------------------------------------------------------------===//

#include "EmbeddedDSLSpot.h"
#include "clang/AST/Decl.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/EmbeddedDSLFramework.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

//===----------------------------------------------------------------------===//
// Main Checker Implementation
//===----------------------------------------------------------------------===//

class EmbeddedDSLMonitorChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols,
                     check::EndFunction, check::EndAnalysis,
                     check::PointerEscape, check::Bind> {

  // Unified DSL monitor (framework modeling + SPOT stepping)
  std::unique_ptr<dsl::DSLMonitor> Monitor;
  // Restrict state tracking to functions referenced in the property (e.g.,
  // malloc/free)
  mutable std::set<std::string> AllowedFns;

  // Generic event generation
  dsl::GenericEvent createPostCallEvent(const CallEvent &Call,
                                        CheckerContext &C) const;
  dsl::GenericEvent createPreCallEvent(const CallEvent &Call,
                                       CheckerContext &C) const;
  dsl::GenericEvent createDeadSymbolsEvent(SymbolRef Sym,
                                           CheckerContext &C) const;

public:
  EmbeddedDSLMonitorChecker() {
    // Create the property definition and monitor automaton
    // Create a generic property with the malloc/free formula
    auto mallocCall = dsl::DSL::Call(
        "malloc", dsl::SymbolBinding(dsl::BindingType::ReturnValue, "x"));
    auto notNull = dsl::DSL::Not(dsl::DSL::Var("x"));
    auto mallocAndNotNull = dsl::DSL::And(mallocCall, dsl::DSL::IsNonNull("x"));

    auto freeCall = dsl::DSL::Call(
        "free", dsl::SymbolBinding(dsl::BindingType::FirstParameter, "x"));
    auto eventuallyFree = dsl::DSL::F(freeCall);
    eventuallyFree->withDiagnostic(
        "resource not destroyed (violates exactly-once)");

    auto freeImpliesNoMoreFree =
        dsl::DSL::Implies(freeCall, dsl::DSL::G(dsl::DSL::Not(freeCall)));
    freeImpliesNoMoreFree->withDiagnostic(
        "resource destroyed twice (violates exactly-once)");

    auto globallyNoMoreFree = dsl::DSL::G(freeImpliesNoMoreFree);
    auto eventuallyFreeAndNoMoreFree =
        dsl::DSL::And(eventuallyFree, globallyNoMoreFree);
    auto implication =
        dsl::DSL::Implies(mallocAndNotNull, eventuallyFreeAndNoMoreFree);
    auto globallyImplication = dsl::DSL::G(implication);
    globallyImplication->withDiagnostic("Memory management property violation");

    auto property = std::make_unique<dsl::GenericProperty>(
        "malloc_free_exactly_once",
        "G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → G ¬free(x) ) )",
        globallyImplication);
    Monitor = dsl::DSLMonitor::create(std::move(property), this);

    // Concise debug: property activation
    auto formulaBuilder = Monitor->getFormulaBuilder();
    llvm::errs() << "EmbeddedDSLMonitor: activating property "
                    "'malloc_free_exactly_once'\n";

    // Always cache allowed function names for state tracking
    AllowedFns = Monitor->getFormulaBuilder().getFunctionNames();
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                     const InvalidatedSymbols &Escaped,
                                     const CallEvent *Call,
                                     PointerEscapeKind Kind) const;
  void checkBind(const SVal &location, const SVal &value, const Stmt *StoreE,
                 bool isInit, CheckerContext &C) const;

private:
  // Move tracking attach to bind of the malloc return into a region; ensures
  // persistence
  void attachTrackingOnBind(SymbolRef Sym, const MemRegion *MR,
                            CheckerContext &C) const {
    if (!Sym || !MR)
      return;
    // Determine formula variable name if known from prior PostCall mapping
    ProgramStateRef Cur = C.getState();
    std::string varName;
    if (const std::string *VN = Cur->get<::GenericSymbolMap>(Sym))
      varName = *VN;
    // Only if the property uses IsNonNull on this DSL variable name.
    // If mapping not yet populated, fall back to common DSL var name "x".
    std::string checkName = varName;
    if (checkName.empty() && Monitor->shouldSplitOnIsNonNull("x"))
      checkName = "x";
    if (checkName.empty() || !Monitor->shouldSplitOnIsNonNull(checkName))
      return;
    // Only attach if the property is using IsNonNull on this variable name 'x'
    // We do not have the DSL variable name here, but our monitor will store
    // GenericSymbolMap afterwards.
    ProgramStateRef S = Cur;
    // If this symbol looks like a malloc return (unknown here), conservatively
    // ensure we don't double-add
    if (!S->contains<::TrackedSymbols>(Sym)) {
      // Use a benign store to persist the state immediately at bind point
      S = S->add<::TrackedSymbols>(Sym);
      // Ensure GenericSymbolMap holds the DSL variable name so sentinel AP
      // names match
      std::string toStore = varName.empty() ? std::string("x") : varName;
      S = S->set<::GenericSymbolMap>(Sym, toStore);
      C.addTransition(S);
      if (dsl::edslDebugEnabled()) {
        unsigned cnt = std::distance(S->get<::TrackedSymbols>().begin(),
                                     S->get<::TrackedSymbols>().end());
        llvm::errs() << "[EDSL][BIND] pre-attach tracked sym_id="
                     << Sym->getSymbolID() << " MR=" << MR->getString()
                     << " var='" << toStore << "' tracked_count=" << cnt
                     << "\n";
      }
    }
  }
};

//===----------------------------------------------------------------------===//
// Generic Event Generation
//===----------------------------------------------------------------------===//

dsl::GenericEvent
EmbeddedDSLMonitorChecker::createPostCallEvent(const CallEvent &Call,
                                               CheckerContext &C) const {
  // Use binding-driven event creation from the monitor
  return Monitor->createBindingDrivenEvent(Call, dsl::EventType::PostCall, C);
}

dsl::GenericEvent
EmbeddedDSLMonitorChecker::createPreCallEvent(const CallEvent &Call,
                                              CheckerContext &C) const {
  // Use binding-driven event creation from the monitor
  return Monitor->createBindingDrivenEvent(Call, dsl::EventType::PreCall, C);
}

dsl::GenericEvent
EmbeddedDSLMonitorChecker::createDeadSymbolsEvent(SymbolRef Sym,
                                                  CheckerContext &C) const {
  std::string symbolName =
      Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";

  return dsl::GenericEvent(dsl::EventType::DeadSymbols, "", symbolName, Sym,
                           SourceLocation());
}

//===----------------------------------------------------------------------===//
// Checker Method Implementations
//===----------------------------------------------------------------------===//

void EmbeddedDSLMonitorChecker::checkPostCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  // Only process functions referenced by the property
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  if (!II)
    return;
  std::string Fn = II->getName().str();
  if (AllowedFns.find(Fn) == AllowedFns.end())
    return;

  // Generate generic event and let the monitor handle it
  auto event = createPostCallEvent(Call, C);
  if (!event.Symbol)
    return;
  // Unified monitor handles modeling + temporal step + diagnostics
  Monitor->handleEvent(event, C);
}

void EmbeddedDSLMonitorChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  // Only process functions referenced by the property
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  if (!II)
    return;
  std::string Fn = II->getName().str();
  if (AllowedFns.find(Fn) == AllowedFns.end())
    return;

  // Generate generic event and let the monitor handle it
  auto event = createPreCallEvent(Call, C);
  // Unified monitor handles modeling + temporal step
  Monitor->handleEvent(event, C);
}

void EmbeddedDSLMonitorChecker::checkDeadSymbols(SymbolReaper &SR,
                                                 CheckerContext &C) const {
  for (const auto *Region : SR.regions()) {
    llvm::errs() << "[EDSL] dead-regions: dying region=" << Region->getString()
                 << " isLive=" << SR.isLiveRegion(Region) << "\n";
  }
  // For each tracked symbol that just became dead, forward a DeadSymbols event.
  ProgramStateRef St = C.getState();
  std::string FnName;
  if (const auto *FD = llvm::dyn_cast_or_null<FunctionDecl>(
          C.getLocationContext() ? C.getLocationContext()->getDecl() : nullptr))
    FnName = FD->getNameAsString();
  if (dsl::edslDebugEnabled()) {
    unsigned n = std::distance(St->get<::TrackedSymbols>().begin(),
                               St->get<::TrackedSymbols>().end());
    llvm::errs() << "[EDSL] dead-symbols: fn='" << FnName
                 << "' tracked_count=" << n << "\n";
    for (auto Sym : St->get<::TrackedSymbols>()) {
      bool live = SR.isLive(Sym);
      std::string name = "sym_" + std::to_string(Sym->getSymbolID());
      if (const std::string *Var = St->get<::GenericSymbolMap>(Sym))
        name = *Var;
      llvm::errs() << "[EDSL] dead-symbols: tracked sym_id="
                   << Sym->getSymbolID() << " name='" << name
                   << "' isLive=" << (live ? "T" : "F") << "\n";
    }
  }
  llvm::SmallVector<SymbolRef, 8> ToRemove;
  for (auto Sym : St->get<::TrackedSymbols>()) {
    if (!Sym)
      continue;
    if (!SR.isLive(Sym)) {
      std::string name = "sym_" + std::to_string(Sym->getSymbolID());
      if (const std::string *Var = St->get<::GenericSymbolMap>(Sym))
        name = *Var;
      if (dsl::edslDebugEnabled()) {
        llvm::errs() << "[EDSL] dead-symbols: emitting DeadSymbols in fn='"
                     << FnName << "' for sym_id=" << Sym->getSymbolID()
                     << " name='" << name << "'\n";
      }
      dsl::GenericEvent ev(dsl::EventType::DeadSymbols, "", name, Sym,
                           SourceLocation());
      Monitor->handleEvent(ev, C);
      ToRemove.push_back(Sym);
    }
  }
  for (auto Sym : ToRemove) {
    St = St->remove<::TrackedSymbols>(Sym);
  }
  if (!ToRemove.empty())
    C.addTransition(St);
}

void EmbeddedDSLMonitorChecker::checkEndFunction(const ReturnStmt *RS,
                                                 CheckerContext &C) const {
  (void)RS;
  // Fallback: only if analysis in this frame still has tracked Active symbols
  // and none died.
  ProgramStateRef St = C.getState();
  llvm::SmallVector<SymbolRef, 8> ToRemove;
  for (auto Sym : St->get<::TrackedSymbols>()) {
    if (!Sym)
      continue;
    const ::SymbolState *CurPtr = St->get<::SymbolStates>(Sym);
    ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
    // Only when Active and the reaper would not report it here (EndFunction
    // usually comes before DeadSymbols)
    if (Cur == ::SymbolState::Active) {
      std::string name = "sym_" + std::to_string(Sym->getSymbolID());
      if (const std::string *Var = St->get<::GenericSymbolMap>(Sym))
        name = *Var;
      if (dsl::edslDebugEnabled()) {
        llvm::errs() << "[EDSL] end-function: synthesizing DeadSymbols "
                        "(fallback) for active sym_id="
                     << Sym->getSymbolID() << " name='" << name << "'\n";
      }
      dsl::GenericEvent ev(dsl::EventType::DeadSymbols, "", name, Sym,
                           SourceLocation());
      Monitor->handleEvent(ev, C);
      ToRemove.push_back(Sym);
    }
  }
  for (auto Sym : ToRemove) {
    St = St->remove<::TrackedSymbols>(Sym);
  }
  if (!ToRemove.empty())
    C.addTransition(St);
}

ProgramStateRef EmbeddedDSLMonitorChecker::checkPointerEscape(
    ProgramStateRef State, const InvalidatedSymbols &Escaped,
    const CallEvent *Call, PointerEscapeKind Kind) const {
  (void)Call;
  (void)Kind;
  // For every escaped symbol, inform the framework to drop local obligations.
  for (SymbolRef Sym : Escaped) {
    if (!Sym)
      continue;
    dsl::GenericEvent escEvt(dsl::EventType::PointerEscape, "",
                             "sym_" + std::to_string(Sym->getSymbolID()), Sym,
                             SourceLocation());
    State = State->remove<::TrackedSymbols>(Sym);
  }
  return State;
}

void EmbeddedDSLMonitorChecker::checkBind(const SVal &location,
                                          const SVal &value, const Stmt *StoreE,
                                          bool isInit,
                                          CheckerContext &C) const {
  // If a symbol is bound into a region, remember it for later nullness checks.
  if (SymbolRef Sym = value.getAsSymbol()) {
    if (const MemRegion *MR = location.getAsRegion()) {
      ProgramStateRef State = C.getState();
      State = State->set<::SymbolToRegionMap>(Sym, MR);
      C.addTransition(State);
      // Attach tracking early to survive path pruning after PostCall
      attachTrackingOnBind(Sym, MR, C);
    }
  }
}

void EmbeddedDSLMonitorChecker::checkEndAnalysis(ExplodedGraph &G,
                                                 BugReporter &BR,
                                                 ExprEngine &Eng) const {
  // Emit EndAnalysis for still-active tracked symbols at terminal nodes
  for (auto I = llvm::GraphTraits<ExplodedGraph *>::nodes_begin(&G),
            E = llvm::GraphTraits<ExplodedGraph *>::nodes_end(&G);
       I != E; ++I) {
    const ExplodedNode *N = *I;
    if (!N)
      continue;
    if (N->succ_empty()) {
      ProgramStateRef S = N->getState();
      if (!S)
        continue;
      for (auto Sym : S->get<::TrackedSymbols>()) {
        if (!Sym)
          continue;
        const ::SymbolState *CurPtr = S->get<::SymbolStates>(Sym);
        ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
        if (Cur == ::SymbolState::Active) {
          std::string name = "sym_" + std::to_string(Sym->getSymbolID());
          if (const std::string *Var = S->get<::GenericSymbolMap>(Sym))
            name = *Var;
          if (dsl::edslDebugEnabled()) {
            llvm::errs() << "[EDSL] end-analysis: emitting EndAnalysis for "
                            "active sym_id="
                         << Sym->getSymbolID() << " name='" << name
                         << "' node=" << (const void *)N << "\n";
          }
          // Use the node's existing tag; we just need a CheckerContext to
          // deliver the event
          CheckerContext TmpCtx(*(NodeBuilder *)nullptr, Eng,
                                const_cast<ExplodedNode *>(N),
                                N->getLocation());
          dsl::GenericEvent ev(dsl::EventType::EndAnalysis, "", name, Sym,
                               SourceLocation());
          Monitor->handleEvent(ev, TmpCtx);
        }
      }
    }
  }

  if (!dsl::edslDebugEnabled())
    return;
  // Dump where TrackedSymbols appear/disappear inside leak_missing_free
  llvm::errs()
      << "[EDSL][DUMP] begin exploded graph dump for leak_missing_free\n";
  for (auto I = llvm::GraphTraits<ExplodedGraph *>::nodes_begin(&G),
            E = llvm::GraphTraits<ExplodedGraph *>::nodes_end(&G);
       I != E; ++I) {
    const ExplodedNode *N = *I;
    if (!N)
      continue;
    ProgramStateRef S = N->getState();
    if (!S)
      continue;
    const LocationContext *LC = N->getLocationContext();
    const auto *FD =
        LC ? llvm::dyn_cast_or_null<FunctionDecl>(LC->getDecl()) : nullptr;
    if (!FD)
      continue;
    std::string Fn = FD->getNameAsString();
    if (Fn != "leak_missing_free")
      continue;
    unsigned count = std::distance(S->get<::TrackedSymbols>().begin(),
                                   S->get<::TrackedSymbols>().end());
    // Compute predecessor tracked count if unique predecessor
    unsigned preCount = 0;
    bool havePre = false;
    if (const ExplodedNode *P = N->getFirstPred()) {
      ProgramStateRef PS = P->getState();
      if (PS) {
        preCount = std::distance(PS->get<::TrackedSymbols>().begin(),
                                 PS->get<::TrackedSymbols>().end());
        havePre = true;
      }
    }
    // Also print node address and immediate successor count for connectivity
    unsigned succs = 0;
    for (const ExplodedNode *Succ : N->succs())
      (void)Succ, ++succs;
    // Print source location if PostStmt
    SourceLocation SL;
    if (auto PS = N->getLocation().getAs<PostStmt>())
      SL = PS->getStmt()->getBeginLoc();
    PresumedLoc PL = Eng.getContext().getSourceManager().getPresumedLoc(SL);
    llvm::errs() << "[EDSL][DUMP] node=" << (const void *)N << " fn='" << Fn
                 << "'"
                 << " loc=" << (PL.isValid() ? PL.getFilename() : "<invalid>")
                 << ":" << (PL.isValid() ? PL.getLine() : 0)
                 << " tracked=" << count << " succs=" << succs;
    if (havePre)
      llvm::errs() << " (pred=" << preCount << ")";
    llvm::errs() << " ids=[";
    bool first = true;
    for (auto Sym : S->get<::TrackedSymbols>()) {
      if (!first)
        llvm::errs() << ",";
      first = false;
      llvm::errs() << Sym->getSymbolID();
    }
    llvm::errs() << "]\n";

    // If tracked just became empty, print predecessor chain up to 3 steps
    if (count == 0 && havePre && preCount > 0) {
      const ExplodedNode *P = N->getFirstPred();
      for (int k = 0; k < 3 && P; ++k) {
        ProgramStateRef PS = P->getState();
        unsigned pc =
            PS ? (unsigned)std::distance(PS->get<::TrackedSymbols>().begin(),
                                         PS->get<::TrackedSymbols>().end())
               : 0;
        llvm::errs() << "[EDSL][TRACE] back " << k + 1
                     << ": node=" << (const void *)P << " tracked=" << pc
                     << " ids=[";
        bool f = true;
        if (PS)
          for (auto Sym : PS->get<::TrackedSymbols>()) {
            if (!f)
              llvm::errs() << ",";
            f = false;
            llvm::errs() << Sym->getSymbolID();
          }
        llvm::errs() << "]\n";
        P = P->getFirstPred();
      }
    }
  }
  llvm::errs() << "[EDSL][DUMP] end exploded graph dump\n";
}

} // namespace

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

void ento::registerEmbeddedDSLMonitor(CheckerManager &mgr) {
  mgr.registerChecker<EmbeddedDSLMonitorChecker>();
}

bool ento::shouldRegisterEmbeddedDSLMonitor(const CheckerManager &mgr) {
  return true;
}
