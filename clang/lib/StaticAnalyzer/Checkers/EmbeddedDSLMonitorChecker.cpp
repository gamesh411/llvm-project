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
#include "EmbeddedDSLSpot.h"
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
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols, check::EndAnalysis> {

  // Dynamic monitor automaton
  std::unique_ptr<dsl::MonitorAutomaton> Monitor;
  // SPOT-backed monitor
  std::unique_ptr<dsl::SpotMonitor> SpotMon;
  // Restrict state tracking to functions referenced in the property (e.g., malloc/free)
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
    auto mallocAndNotNull = dsl::DSL::And(mallocCall, notNull);

    auto freeCall = dsl::DSL::Call(
        "free", dsl::SymbolBinding(dsl::BindingType::FirstParameter, "x"));
    auto eventuallyFree = dsl::DSL::F(freeCall);
    eventuallyFree->withDiagnostic("Memory leak: allocated memory not freed");

    auto freeImpliesNoMoreFree =
        dsl::DSL::Implies(freeCall, dsl::DSL::G(dsl::DSL::Not(freeCall)));
    freeImpliesNoMoreFree->withDiagnostic(
        "Double free: memory freed multiple times");

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
    Monitor =
        std::make_unique<dsl::MonitorAutomaton>(std::move(property), this);

    // Concise debug: property activation
    auto formulaBuilder = Monitor->getFormulaBuilder();
    llvm::errs() << "EmbeddedDSLMonitor: activating property 'malloc_free_exactly_once'\n";

    // Build SPOT monitor for this property
    auto fb = Monitor->getFormulaBuilder();
    auto res = dsl::buildSpotMonitorFromDSL(fb);
    if (res.Monitor) {
      SpotMon = std::make_unique<dsl::SpotMonitor>(std::move(res.Monitor), std::move(res.Registry), fb);
    }
    // Always cache allowed function names for state tracking (works without SPOT)
    AllowedFns = Monitor->getFormulaBuilder().getFunctionNames();
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;
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
  // Only update internal state when symbol is non-null
  Monitor->handleEvent(event, C);
  if (SpotMon) {
    auto violated = SpotMon->step(event, C);
    if (!violated.empty()) {
      std::string msg = SpotMon->selectDiagnosticForViolation(violated);
      if (msg.empty()) msg = "temporal property violated";
      if (event.Symbol) {
        ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
        if (ErrorNode) {
          static const BugType GenericBT{this, "temporal_violation", "EmbeddedDSLMonitor"};
          auto R = std::make_unique<PathSensitiveBugReport>(GenericBT, msg, ErrorNode);
          R->markInteresting(event.Symbol);
          C.emitReport(std::move(R));
        }
      }
    }
  }
  // Update generic symbol state based on event to support diagnostics
  if (event.Symbol && AllowedFns.find(event.FunctionName) != AllowedFns.end()) {
    ProgramStateRef State = C.getState();
    if (event.Type == dsl::EventType::PostCall) {
      // Treat as creation (e.g., malloc result)
      State = State->set<::SymbolStates>(event.Symbol, ::SymbolState::Active);
      State = State->add<::PendingLeakSet>(event.Symbol);
      // Add a binding note similar to framework format
      std::string internal = "sym_" + std::to_string(event.Symbol->getSymbolID());
      std::string var = event.SymbolName.empty() ? std::string("x") : event.SymbolName;
      std::string note = std::string("symbol \"") + var + "\" is bound here (internal symbol: " + internal + ")";
      const NoteTag *NT = C.getNoteTag([note]() { return note; });
      C.addTransition(State, NT);
    } else if (event.Type == dsl::EventType::PreCall) {
      // Treat as destruction (e.g., free parameter)
      const ::SymbolState *CurPtr = State->get<::SymbolStates>(event.Symbol);
      ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
      if (Cur == ::SymbolState::Active) {
        State = State->set<::SymbolStates>(event.Symbol, ::SymbolState::Inactive);
        // Purge from GenericSymbolMap as well to avoid dangling entries
        State = State->remove<::GenericSymbolMap>(event.Symbol);
        State = State->remove<::PendingLeakSet>(event.Symbol);
        C.addTransition(State);
      } else if (Cur == ::SymbolState::Inactive) {
        // Double free
        ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
        if (ErrorNode) {
          static const BugType BT{this, "temporal_violation", "EmbeddedDSLMonitor"};
          std::string msg = "resource destroyed twice (violates exactly-once)";
          std::string internal = "sym_" + std::to_string(event.Symbol->getSymbolID());
          msg += " (internal symbol: " + internal + ")";
          auto R = std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
          R->markInteresting(event.Symbol);
          C.emitReport(std::move(R));
        }
      }
    }
  }
  // Leak reporting happens at DeadSymbols only
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
  if (!event.Symbol)
    return;
  Monitor->handleEvent(event, C);
  if (SpotMon) {
    (void)SpotMon->step(event, C);
  }
}

void EmbeddedDSLMonitorChecker::checkDeadSymbols(SymbolReaper &SR,
                                                 CheckerContext &C) const {
  // Generate events for all dead symbols
  ProgramStateRef State = C.getState();

  for (auto [Sym, Value] : State->get<::GenericSymbolMap>()) {
    if (SR.isDead(Sym)) {
      // This symbol is dead and was tracked - report leak
      auto event = createDeadSymbolsEvent(Sym, C);
      // Emit leak if still Active
      const ::SymbolState *CurPtr = State->get<::SymbolStates>(Sym);
      ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
      if (Cur == ::SymbolState::Active && State->contains<::PendingLeakSet>(Sym)) {
        ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
        if (ErrorNode) {
          static const BugType BT{this, "temporal_violation", "EmbeddedDSLMonitor"};
          std::string msg = "resource not destroyed (violates exactly-once)";
          std::string internal = "sym_" + std::to_string(Sym->getSymbolID());
          msg += " (internal symbol: " + internal + ")";
          auto R = std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
          R->markInteresting(Sym);
          C.emitReport(std::move(R));
        }
      }
      // Cleanup maps for this dead symbol
      State = State->remove<::GenericSymbolMap>(Sym);
      State = State->remove<::SymbolStates>(Sym);
      State = State->remove<::PendingLeakSet>(Sym);
      C.addTransition(State);
    }
  }

  // Also check SymbolStates map for dead symbols
  for (auto [Sym, SValState] : State->get<::SymbolStates>()) {
    if (SValState == ::SymbolState::Active && SR.isDead(Sym) && State->contains<::PendingLeakSet>(Sym)) {
      // Emit leak as above for any leftover active symbol
      ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
      if (ErrorNode) {
        static const BugType BT{this, "temporal_violation", "EmbeddedDSLMonitor"};
        std::string msg = "resource not destroyed (violates exactly-once)";
        std::string internal = "sym_" + std::to_string(Sym->getSymbolID());
        msg += " (internal symbol: " + internal + ")";
        auto R = std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
        R->markInteresting(Sym);
        C.emitReport(std::move(R));
      }
      // Cleanup
      State = State->remove<::GenericSymbolMap>(Sym);
      State = State->remove<::SymbolStates>(Sym);
      State = State->remove<::PendingLeakSet>(Sym);
      C.addTransition(State);
    }
  }
}

void EmbeddedDSLMonitorChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  // End-of-analysis hook: in future, iterate remaining states/monitors
  // and emit eventuality violations. Currently handled via DeadSymbols.
  (void)G; (void)BR; (void)Eng;
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
