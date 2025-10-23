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
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols, check::EndFunction, check::EndAnalysis, check::PointerEscape> {

  // Unified DSL monitor (framework modeling + SPOT stepping)
  std::unique_ptr<dsl::DSLMonitor> Monitor;
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
    Monitor = dsl::DSLMonitor::create(std::move(property), this);

    // Concise debug: property activation
    auto formulaBuilder = Monitor->getFormulaBuilder();
    llvm::errs() << "EmbeddedDSLMonitor: activating property 'malloc_free_exactly_once'\n";

    // Always cache allowed function names for state tracking
    AllowedFns = Monitor->getFormulaBuilder().getFunctionNames();
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                     const InvalidatedSymbols &Escaped,
                                     const CallEvent *Call,
                                     PointerEscapeKind Kind) const;
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
  // We no longer rely on symbol liveness for leak location placement.
  // Leak reporting is finalized in checkEndFunction by inspecting PendingLeakSet.
  (void)SR;
  (void)C;
}

void EmbeddedDSLMonitorChecker::checkEndFunction(const ReturnStmt *RS,
                                                 CheckerContext &C) const {
  (void)RS;
  // Forward a generic EndFunction event; unified monitor steps and models
  dsl::GenericEvent endEvt(dsl::EventType::EndFunction, "", "", nullptr, SourceLocation());
  Monitor->handleEvent(endEvt, C);
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
    dsl::GenericEvent escEvt(dsl::EventType::PointerEscape, "", "sym_" + std::to_string(Sym->getSymbolID()), Sym, SourceLocation());
    // Use a dummy CheckerContext-less path? We need a context to transition.
    // Here, we can't emit transitions; just mark by removing PendingLeakSet directly via State.
    // However, to keep all modeling in framework, we approximate by clearing here too.
    // Prefer forwarding via Monitor when context is available; CSA provides only State in this callback.
    State = State->remove<::PendingLeakSet>(Sym);
  }
  return State;
}

void EmbeddedDSLMonitorChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  // Safety net: if any symbol still has a pending obligation across final states,
  // emit a conservative leak diagnostic. Location quality may be worse.
  for (auto I = llvm::GraphTraits<ExplodedGraph *>::nodes_begin(&G),
            E = llvm::GraphTraits<ExplodedGraph *>::nodes_end(&G);
       I != E; ++I) {
    const ExplodedNode *N = *I;
    ProgramStateRef S = N ? N->getState() : nullptr;
    if (!S)
      continue;
    for (auto Sym : S->get<::PendingLeakSet>()) {
      // Prefer using the last node for the path; create a report per symbol.
      static const BugType BT{this, "temporal_violation_end_analysis", "EmbeddedDSLMonitor"};
      ExplodedNode *EN = const_cast<ExplodedNode *>(N);
      std::string internal = "sym_" + std::to_string(Sym->getSymbolID());
      std::string Msg =
          "resource not destroyed before analysis end (violates exactly-once)";
      Msg += " (internal symbol: " + internal + ")";
      Msg += " [reported at EndAnalysis; not all program paths may have been fully explored]";
      auto R = std::make_unique<PathSensitiveBugReport>(BT, Msg, EN);
      R->markInteresting(Sym);
      BR.emitReport(std::move(R));
    }
  }
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
