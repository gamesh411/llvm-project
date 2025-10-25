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

// Define all GDM traits in this translation unit to avoid
// multiple definition issues across translation units
REGISTER_SET_WITH_PROGRAMSTATE(TrackedSymbols, clang::ento::SymbolRef)
REGISTER_MAP_WITH_PROGRAMSTATE(GenericSymbolMap, clang::ento::SymbolRef,
                               std::string)
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolStates, clang::ento::SymbolRef,
                               SymbolState)
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolToRegionMap, clang::ento::SymbolRef,
                               const clang::ento::MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(AutomatonState, clang::ento::SymbolRef, int)
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolToFormulaVar, clang::ento::SymbolRef,
                               std::string)

// Implement API functions to access TrackedSymbols trait from other translation
// units
namespace clang {
namespace ento {
namespace dsl {

ProgramStateRef addTrackedSymbol(ProgramStateRef State, SymbolRef Sym) {
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][API] addTrackedSymbol: state="
                 << (const void *)State.get()
                 << " sym_id=" << (Sym ? Sym->getSymbolID() : 0) << "\n";
  }
  ProgramStateRef result = State->add<TrackedSymbols>(Sym);
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][API] addTrackedSymbol: result_state="
                 << (const void *)result.get()
                 << " added sym_id=" << (Sym ? Sym->getSymbolID() : 0) << "\n";
  }
  return result;
}

ProgramStateRef removeTrackedSymbol(ProgramStateRef State, SymbolRef Sym) {
  return State->remove<TrackedSymbols>(Sym);
}

bool containsTrackedSymbol(ProgramStateRef State, SymbolRef Sym) {
  bool result = State->get<TrackedSymbols>().contains(Sym);
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][API] containsTrackedSymbol: state="
                 << (const void *)State.get()
                 << " sym_id=" << (Sym ? Sym->getSymbolID() : 0)
                 << " result=" << result << "\n";
  }
  return result;
}

size_t getTrackedSymbolCount(ProgramStateRef State) {
  size_t count = 0;
  for (auto Sym : State->get<TrackedSymbols>()) {
    count++;
  }
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][API] getTrackedSymbolCount: state="
                 << (const void *)State.get() << " count=" << count << "\n";
  }
  return count;
}

std::vector<SymbolRef> getTrackedSymbols(ProgramStateRef State) {
  std::vector<SymbolRef> symbols;
  for (auto Sym : State->get<TrackedSymbols>()) {
    symbols.push_back(Sym);
  }
  return symbols;
}

// GenericSymbolMap API implementations
ProgramStateRef setGenericSymbolMap(ProgramStateRef State, SymbolRef Sym,
                                    const std::string &Value) {
  return State->set<GenericSymbolMap>(Sym, Value);
}

ProgramStateRef removeGenericSymbolMap(ProgramStateRef State, SymbolRef Sym) {
  return State->remove<GenericSymbolMap>(Sym);
}

const std::string *getGenericSymbolMap(ProgramStateRef State, SymbolRef Sym) {
  return State->get<GenericSymbolMap>(Sym);
}

bool hasGenericSymbolMap(ProgramStateRef State, SymbolRef Sym) {
  return State->get<GenericSymbolMap>(Sym) != nullptr;
}

// SymbolStates API implementations
ProgramStateRef setSymbolState(ProgramStateRef State, SymbolRef Sym,
                               SymbolState SymbolState) {
  return State->set<SymbolStates>(Sym, SymbolState);
}

const SymbolState *getSymbolState(ProgramStateRef State, SymbolRef Sym) {
  return State->get<SymbolStates>(Sym);
}

bool isSymbolActive(ProgramStateRef State, SymbolRef Sym) {
  if (const SymbolState *CurPtr = State->get<SymbolStates>(Sym))
    return *CurPtr == SymbolState::Active;
  return false;
}

bool isSymbolInactive(ProgramStateRef State, SymbolRef Sym) {
  if (const SymbolState *CurPtr = State->get<SymbolStates>(Sym))
    return *CurPtr == SymbolState::Inactive;
  return false;
}

// SymbolToRegionMap API implementations
ProgramStateRef setSymbolToRegionMap(ProgramStateRef State, SymbolRef Sym,
                                     const MemRegion *Region) {
  return State->set<SymbolToRegionMap>(Sym, Region);
}

const MemRegion *getSymbolToRegionMap(ProgramStateRef State, SymbolRef Sym) {
  if (const MemRegion *const *RegionPtr = State->get<SymbolToRegionMap>(Sym)) {
    return *RegionPtr;
  }
  return nullptr;
}

// AutomatonState API implementations
ProgramStateRef setAutomatonState(ProgramStateRef State, SymbolRef Sym,
                                  int StateValue) {
  return State->set<AutomatonState>(Sym, StateValue);
}

const int *getAutomatonState(ProgramStateRef State, SymbolRef Sym) {
  return State->get<AutomatonState>(Sym);
}

ProgramStateRef removeAutomatonState(ProgramStateRef State, SymbolRef Sym) {
  return State->remove<AutomatonState>(Sym);
}

// Symbol-Formula Variable Mapping API implementations
ProgramStateRef setSymbolFormulaMapping(ProgramStateRef State, SymbolRef Sym,
                                        const std::string &VarName) {
  return State->set<SymbolToFormulaVar>(Sym, VarName);
}

const std::string *getSymbolFormulaVar(ProgramStateRef State, SymbolRef Sym) {
  return State->get<SymbolToFormulaVar>(Sym);
}

ProgramStateRef removeSymbolFormulaMapping(ProgramStateRef State,
                                           SymbolRef Sym) {
  return State->remove<SymbolToFormulaVar>(Sym);
}

} // namespace dsl
} // namespace ento
} // namespace clang

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

public:
  EmbeddedDSLMonitorChecker() {
    // Create the property definition and monitor automaton
    // Create a generic property with the malloc/free formula
    using namespace clang::ast_matchers;
    auto mallocMatcher =
        callExpr(callee(functionDecl(hasName("malloc"))), argumentCountIs(1));
    auto mallocCall = dsl::DSL::Call(
        mallocMatcher,
        dsl::SymbolBinding(dsl::BindingType::ReturnValueNonNull, "x"));

    auto freeMatcher = callExpr(callee(functionDecl(hasName("free"))),
                                argumentCountIs(1), hasArgument(0, expr()));
    auto freeCall = dsl::DSL::Call(
        freeMatcher, dsl::SymbolBinding(dsl::BindingType::FirstParameter, "x"));
    auto eventuallyFree = dsl::DSL::F(freeCall);
    eventuallyFree->withDiagnostic(
        "resource not destroyed (violates exactly-once)");

    auto freeImpliesNoMoreFree = dsl::DSL::Implies(
        freeCall, dsl::DSL::X(dsl::DSL::G(dsl::DSL::Not(freeCall))));
    freeImpliesNoMoreFree->withDiagnostic(
        "resource destroyed twice (violates exactly-once)");

    auto globallyNoMoreFree = dsl::DSL::G(freeImpliesNoMoreFree);
    auto eventuallyFreeAndNoMoreFree =
        dsl::DSL::And(eventuallyFree, globallyNoMoreFree);
    auto implication =
        dsl::DSL::Implies(mallocCall, eventuallyFreeAndNoMoreFree);
    auto globallyImplication = dsl::DSL::G(implication);
    globallyImplication->withDiagnostic("Memory management property violation");

    auto property = std::make_unique<dsl::GenericProperty>(
        "malloc_free_exactly_once",
        "G( malloc(x non null) → F free(x) ∧ G( free(x) → G X(¬free(x)) ) )",
        globallyImplication);
    Monitor = dsl::DSLMonitor::create(std::move(property), this);

    // Concise debug: property activation
    llvm::errs() << "EmbeddedDSLMonitor: activating property "
                    "'malloc_free_exactly_once'\n";
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
};

//===----------------------------------------------------------------------===//
// Checker Method Implementations
//===----------------------------------------------------------------------===//

void EmbeddedDSLMonitorChecker::checkPostCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][TRACE] checkPostCall: call=" << Call.getOriginExpr()
                 << " fn='" << Call.getCalleeIdentifier()->getName().str()
                 << "' tracked_before="
                 << dsl::getTrackedSymbolCount(C.getState())
                 << " node=" << C.getPredecessor()
                 << " state=" << (const void *)C.getState().get() << "\n";
  }

  // Generate generic event and let the monitor handle it
  auto event = Monitor->createPostCallEvent(Call, C);

  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][POSTCALL] event.Symbol="
                 << (event.Symbol ? "valid" : "null") << " event.SymbolName='"
                 << event.SymbolName << "'\n";
  }

  Monitor->handleEvent(event, C);
}

void EmbeddedDSLMonitorChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][TRACE] checkPreCall: call=" << Call.getOriginExpr()
                 << " fn='" << Call.getCalleeIdentifier()->getName().str()
                 << "' tracked_before="
                 << dsl::getTrackedSymbolCount(C.getState())
                 << " node=" << C.getPredecessor()
                 << " state=" << (const void *)C.getState().get() << "\n";
  }

  auto event = Monitor->createPreCallEvent(Call, C);

  Monitor->handleEvent(event, C);
}

void EmbeddedDSLMonitorChecker::checkDeadSymbols(SymbolReaper &SR,
                                                 CheckerContext &C) const {
  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][TRACE] checkDeadSymbols node=" << C.getPredecessor()
                 << " state=" << (const void *)C.getState().get() << "\n";
  }

  // Minimal forwarding: for each tracked symbol that just became dead, emit a
  // DeadSymbols event; the framework handles diagnostics and state updates.
  ProgramStateRef State = C.getState();
  if (dsl::edslDebugEnabled()) {
    unsigned tracked = dsl::getTrackedSymbolCount(State);
    llvm::errs() << "[EDSL][TRACE] tracked_count=" << tracked << " ids=[";
    bool first = true;
    for (auto S : dsl::getTrackedSymbols(State)) {
      if (!first)
        llvm::errs() << ",";
      first = false;
      llvm::errs() << S->getSymbolID();
    }
    llvm::errs() << "]\n";
  }

  for (auto Sym : dsl::getTrackedSymbols(State)) {
    if (dsl::edslDebugEnabled()) {
      llvm::errs() << "[EDSL][DEADSYM] checking sym_id=" << Sym->getSymbolID()
                   << " isLive=" << SR.isLive(Sym)
                   << " isDead=" << SR.isDead(Sym) << "\n";
    }
    if (SR.isLive(Sym))
      continue;

    std::string name = "sym_" + std::to_string(Sym->getSymbolID());
    if (const std::string *Var = dsl::getGenericSymbolMap(State, Sym))
      name = *Var;

    if (dsl::edslDebugEnabled()) {
      llvm::errs() << "[EDSL][TRACE] emitting DeadSymbols for sym_id="
                   << Sym->getSymbolID() << " name='" << name << "'\n";
    }

    // Check for leak detection: if symbol is tracked and active, it's a leak
    // We can't emit the error here because checkDeadSymbols can't create error
    // nodes, so we defer it to checkEndFunction/checkEndAnalysis
    if (dsl::edslDebugEnabled()) {
      bool stHasSymbol = dsl::containsTrackedSymbol(State, Sym);
      size_t trackedCount = dsl::getTrackedSymbolCount(State);
      llvm::errs() << "[EDSL][CHECKER] checking for leak with St="
                   << (const void *)State.get()
                   << " St->contains=" << stHasSymbol
                   << " tracked_count=" << trackedCount;
      if (trackedCount > 0) {
        llvm::errs() << " tracked_ids=[";
        for (auto S : dsl::getTrackedSymbols(State)) {
          llvm::errs() << S->getSymbolID() << " ";
        }
        llvm::errs() << "]";
      } else {
        llvm::errs() << " tracked_ids=[]";
      }
      llvm::errs() << "\n";
    }

    if (dsl::containsTrackedSymbol(State, Sym)) {
      if (const ::SymbolState *CurPtr = dsl::getSymbolState(State, Sym)) {
        if (dsl::edslDebugEnabled()) {
          llvm::errs() << "[EDSL][LEAK] symbol state=" << (int)*CurPtr << "\n";
        }
        if (*CurPtr == ::SymbolState::Active) {
          if (dsl::edslDebugEnabled()) {
            llvm::errs() << "[EDSL][LEAK] Detected leak for sym_id="
                         << Sym->getSymbolID() << " - deferring report\n";
          }

          // Create deferred leak report instead of emitting immediately
          std::string msg = "resource not destroyed (violates exactly-once)";
          msg += std::string(" (internal symbol: sym_") +
                 std::to_string(Sym->getSymbolID()) + ")";

          // Use the current location from the checker context
          SourceLocation Loc = C.getLocationContext()->getDecl()->getLocation();
          Monitor->addDeferredLeakReport(msg, "temporal_violation",
                                         "EmbeddedDSLMonitor", Sym, State, Loc);
        }
      }
    }
  }
}

void EmbeddedDSLMonitorChecker::checkEndFunction(const ReturnStmt *RS,
                                                 CheckerContext &C) const {
  (void)RS;
  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][TRACE] checkEndFunction node=" << C.getPredecessor()
                 << " state=" << (const void *)C.getState().get() << "\n";
  }

  // Emit any deferred leak reports that were collected in checkDeadSymbols
  Monitor->emitDeferredLeakReports(C);

  // Clear the deferred reports after emitting them
  Monitor->clearDeferredLeakReports();

  Monitor->handleEvent(dsl::EndFunctionEvent(), C);
}

ProgramStateRef EmbeddedDSLMonitorChecker::checkPointerEscape(
    ProgramStateRef State, const InvalidatedSymbols &Escaped,
    const CallEvent *Call, PointerEscapeKind Kind) const {
  (void)Call;
  (void)Kind;

  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][TRACE] checkPointerEscape, kind=" << Kind
                 << ", call=" << Call->getOriginExpr() << " fn='"
                 << (Call ? Call->getCalleeIdentifier()->getName().str()
                          : "nullptr")
                 << "'\n";
    for (SymbolRef Sym : Escaped) {
      llvm::errs() << "[EDSL][TRACE] sym_id=" << Sym->getSymbolID() << " name='"
                   << "sym_" + std::to_string(Sym->getSymbolID()) << "'\n";
    }
  }
  // For every escaped symbol, inform the framework to drop local obligations.
  for (SymbolRef Sym : Escaped) {
    if (!Sym)
      continue;
    dsl::PointerEscapeEvent escEvt{
        std::string("sym_") + std::to_string(Sym->getSymbolID()), Sym};

    if (dsl::edslDebugEnabled()) {
      llvm::errs()
          << "[EDSL][TRACE] would be emitting PointerEscape event for sym_id="
          << Sym->getSymbolID() << " name='" << escEvt.SymbolName
          << "', but we do not have a CheckerContext to give to handleEvent. "
             "TODO: is there a way to get the CheckerContext from the "
             "ProgramStateRef or CallEvent?\n";
    }
  }
  return State;
}

void EmbeddedDSLMonitorChecker::checkBind(const SVal &location,
                                          const SVal &value, const Stmt *StoreE,
                                          bool isInit,
                                          CheckerContext &C) const {
  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][TRACE] checkBind, isInit=" << isInit
                 << " node=" << C.getPredecessor()
                 << " state=" << (const void *)C.getState().get()
                 << ", location=";
    location.dump();
    llvm::errs() << ", value=";
    value.dump();
    llvm::errs() << ", storeE=";
    StoreE->dump();
    llvm::errs() << "\n";
  }
  // Forward a generic Bind event to the framework/monitor; keep checker
  // minimal.
  SymbolRef Sym = value.getAsSymbol();
  const MemRegion *MR = location.getAsRegion();
  if (!Sym)
    return;
  // Use existing mapping to DSL variable if present; otherwise use "x"
  ProgramStateRef S = C.getState();
  std::string name =
      Sym && dsl::getGenericSymbolMap(S, Sym)
          ? *dsl::getGenericSymbolMap(S, Sym)
          : std::string("sym_") + std::to_string(Sym->getSymbolID());

  dsl::BindEvent ev{name, Sym, MR, StoreE};

  if (dsl::edslDebugEnabled()) {
    llvm::errs() << "[EDSL][TRACE] emitting Bind event for sym_id="
                 << Sym->getSymbolID() << " name='" << name << "'\n";
  }

  Monitor->handleEvent(ev, C);
}

static void dumpExplodedGraphForFunction(ExplodedGraph &G, BugReporter &BR,
                                         ExprEngine &Eng,
                                         const std::string &FnToDump) {
  llvm::errs() << "[EDSL][DUMP] begin exploded graph dump for function '"
               << FnToDump << "'\n";
  // Create a map of node pointers to their indices for easier reference
  std::map<const ExplodedNode *, unsigned> NodeToIndex;
  unsigned index = 0;
  for (auto I = llvm::GraphTraits<ExplodedGraph *>::nodes_begin(&G),
            E = llvm::GraphTraits<ExplodedGraph *>::nodes_end(&G);
       I != E; ++I) {
    NodeToIndex[*I] = index++;
  }

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
    if (Fn != FnToDump)
      continue;
    unsigned count = dsl::getTrackedSymbolCount(S);
    // Compute predecessor tracked count if unique predecessor
    unsigned preCount = 0;
    bool havePre = false;
    if (const ExplodedNode *P = N->getFirstPred()) {
      ProgramStateRef PS = P->getState();
      if (PS) {
        preCount = dsl::getTrackedSymbolCount(PS);
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
    llvm::errs() << "[EDSL][DUMP] node=" << (const void *)N
                 << " idx=" << NodeToIndex[N] << " fn='" << Fn << "'"
                 << " loc=" << (PL.isValid() ? PL.getFilename() : "<invalid>")
                 << ":" << (PL.isValid() ? PL.getLine() : 0)
                 << " tracked=" << count << " succs=" << succs;
    if (havePre) {
      const ExplodedNode *P = N->getFirstPred();
      llvm::errs() << " (pred=" << (const void *)P << " idx=" << NodeToIndex[P]
                   << " tracked=" << preCount << ")";
    }
    llvm::errs() << " ids=[";
    bool first = true;
    for (auto Sym : dsl::getTrackedSymbols(S)) {
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
        unsigned pc = PS ? dsl::getTrackedSymbolCount(PS) : 0;
        llvm::errs() << "[EDSL][TRACE] back " << k + 1
                     << ": node=" << (const void *)P << " tracked=" << pc
                     << " ids=[";
        bool f = true;
        if (PS)
          for (auto Sym : dsl::getTrackedSymbols(PS)) {
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
  llvm::errs() << "[EDSL][DUMP] end exploded graph dump for function '"
               << FnToDump << "'\n";
}

void EmbeddedDSLMonitorChecker::checkEndAnalysis(ExplodedGraph &G,
                                                 BugReporter &BR,
                                                 ExprEngine &Eng) const {
  if (dsl::edslDebugEnabled()) {
    dumpExplodedGraphForFunction(G, BR, Eng, "leak_missing_free");
  }

  // Emit any remaining deferred leak reports
  // Note: We can't use CheckerContext here, so we need to create a dummy one
  // or handle this differently. For now, we'll just clear them.
  Monitor->clearDeferredLeakReports();
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
