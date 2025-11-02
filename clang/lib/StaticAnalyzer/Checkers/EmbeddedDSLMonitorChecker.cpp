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
#include "clang/AST/Expr.h"
#include "clang/AST/ExprObjC.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/EmbeddedDSLFramework.h" // for G
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/Support/raw_ostream.h"
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace clang::ento {
class BugReporter;
class CallEvent;
class CheckerContext;
class ExplodedGraph;
class ExprEngine;
} // namespace clang::ento

namespace {

using namespace clang;
using namespace ento;
using namespace ast_matchers;

//===----------------------------------------------------------------------===//
// Main Checker Implementation
//===----------------------------------------------------------------------===//

class EmbeddedDSLMonitorChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols,
                     check::EndAnalysis> {

  std::unique_ptr<dsl::DSLMonitor> Monitor;

public:
  EmbeddedDSLMonitorChecker() {
    // Create the property definition and monitor automaton
    // Create a generic property with the malloc/free formula
    using namespace clang::ast_matchers;
    auto mallocMatcher =
        callExpr(callee(functionDecl(hasName("malloc"))), argumentCountIs(1));
    auto mallocCall = dsl::DSL::Called(
        mallocMatcher,
        dsl::SymbolBinding(dsl::BindingType::ReturnValueNonNull, "x"));

    auto freeMatcher = callExpr(callee(functionDecl(hasName("free"))),
                                argumentCountIs(1), hasArgument(0, expr()));
    auto freeCall = dsl::DSL::Called(
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

    auto Property = std::make_unique<dsl::PropertyDefinition>(
        "malloc_free_exactly_once",
        "G( malloc(return value 'x') ∧ x non null → F free(first parameter "
        "'x') ∧ G( free(first parameter 'x') → G X(¬free(first parameter 'x')) "
        ") )",
        globallyImplication);
    Monitor = std::make_unique<dsl::DSLMonitor>(this, std::move(Property));

    // Concise debug: property activation
    llvm::errs() << "EmbeddedDSLMonitor: activating property "
                    "'malloc_free_exactly_once'\n";
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;
};

//===----------------------------------------------------------------------===//
// Checker Method Implementations
//===----------------------------------------------------------------------===//

void EmbeddedDSLMonitorChecker::checkPostCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  Monitor->handleEvent(dsl::PostCallEvent{Call, C});
}

void EmbeddedDSLMonitorChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  Monitor->handleEvent(dsl::PreCallEvent{Call, C});
}

void EmbeddedDSLMonitorChecker::checkDeadSymbols(SymbolReaper &SR,
                                                 CheckerContext &C) const {
  Monitor->handleEvent(dsl::DeadSymbolsEvent{
      [&SR](SymbolRef Sym) { return SR.isDead(Sym); }, C});
}

void EmbeddedDSLMonitorChecker::checkEndAnalysis(ExplodedGraph &G,
                                                 BugReporter &BR,
                                                 ExprEngine &Eng) const {
  Monitor->handleEvent(dsl::EndAnalysisEvent{G, BR, Eng});
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
