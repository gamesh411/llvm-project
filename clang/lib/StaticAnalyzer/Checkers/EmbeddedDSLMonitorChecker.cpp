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
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols> {

  // Dynamic monitor automaton
  std::unique_ptr<dsl::MonitorAutomaton> Monitor;

  // Generic event generation
  GenericEvent createPostCallEvent(const CallEvent &Call,
                                   CheckerContext &C) const;
  GenericEvent createPreCallEvent(const CallEvent &Call,
                                  CheckerContext &C) const;
  GenericEvent createDeadSymbolsEvent(SymbolRef Sym, CheckerContext &C) const;

public:
  EmbeddedDSLMonitorChecker() {
    // Create the property definition and monitor automaton
    auto property = std::make_unique<dsl::MallocFreeProperty>();
    Monitor =
        std::make_unique<dsl::MonitorAutomaton>(std::move(property), this);

    // Debug: Print the DSL formula structure
    auto formulaBuilder = Monitor->getFormulaBuilder();
    llvm::errs() << "=== Embedded DSL Formula Structure ===\n";
    llvm::errs() << "Formula: " << formulaBuilder.getFormulaString() << "\n";
    llvm::errs() << "Structural Info: " << formulaBuilder.getStructuralInfo()
                 << "\n";

    auto labels = formulaBuilder.getDiagnosticLabels();
    llvm::errs() << "Diagnostic Labels (" << labels.size() << "):\n";
    for (const auto &label : labels) {
      llvm::errs() << "  - " << label << "\n";
    }

    auto bindings = formulaBuilder.getSymbolBindings();
    llvm::errs() << "Symbol Bindings (" << bindings.size() << "):\n";
    for (const auto &binding : bindings) {
      std::string typeStr;
      switch (binding.Type) {
      case dsl::BindingType::ReturnValue:
        typeStr = "ReturnValue";
        break;
      case dsl::BindingType::FirstParameter:
        typeStr = "FirstParameter";
        break;
      case dsl::BindingType::NthParameter:
        typeStr = "NthParameter";
        break;
      case dsl::BindingType::Variable:
        typeStr = "Variable";
        break;
      }
      llvm::errs() << "  - " << binding.SymbolName << " (" << typeStr << ")\n";
    }

    auto functions = formulaBuilder.getFunctionNames();
    llvm::errs() << "Function Names (" << functions.size() << "):\n";
    for (const auto &func : functions) {
      llvm::errs() << "  - " << func << "\n";
    }
    llvm::errs() << "=====================================\n";

    // Debug: Print Büchi automaton information
    llvm::errs() << "=== Büchi Automaton Information ===\n";
    auto automaton = formulaBuilder.generateAutomaton();
    llvm::errs() << "Automaton States (" << automaton->getStates().size()
                 << "):\n";
    for (const auto &state : automaton->getStates()) {
      llvm::errs() << "  State: " << state->StateID;
      if (state->IsAccepting) {
        llvm::errs() << " (accepting)";
      }
      llvm::errs() << "\n";

      if (!state->AtomicPropositions.empty()) {
        llvm::errs() << "    Atomic Propositions: ";
        for (const auto &prop : state->AtomicPropositions) {
          llvm::errs() << prop << " ";
        }
        llvm::errs() << "\n";
      }

      if (!state->PendingFormulas.empty()) {
        llvm::errs() << "    Pending Formulas: ";
        for (const auto &formula : state->PendingFormulas) {
          llvm::errs() << formula << " ";
        }
        llvm::errs() << "\n";
      }
    }
    llvm::errs() << "=====================================\n";
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
};

//===----------------------------------------------------------------------===//
// Generic Event Generation
//===----------------------------------------------------------------------===//

GenericEvent
EmbeddedDSLMonitorChecker::createPostCallEvent(const CallEvent &Call,
                                               CheckerContext &C) const {
  std::string funcName = Call.getCalleeIdentifier()
                             ? Call.getCalleeIdentifier()->getName().str()
                             : "unknown";

  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  std::string symbolName =
      Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";

  return GenericEvent(EventType::PostCall, funcName, symbolName, Sym, &Call);
}

GenericEvent
EmbeddedDSLMonitorChecker::createPreCallEvent(const CallEvent &Call,
                                              CheckerContext &C) const {
  std::string funcName = Call.getCalleeIdentifier()
                             ? Call.getCalleeIdentifier()->getName().str()
                             : "unknown";

  SymbolRef Sym = Call.getArgSVal(0).getAsSymbol();
  std::string symbolName =
      Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";

  return GenericEvent(EventType::PreCall, funcName, symbolName, Sym, &Call);
}

GenericEvent
EmbeddedDSLMonitorChecker::createDeadSymbolsEvent(SymbolRef Sym,
                                                  CheckerContext &C) const {
  std::string symbolName =
      Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";

  return GenericEvent(EventType::DeadSymbols, "", symbolName, Sym, nullptr);
}

//===----------------------------------------------------------------------===//
// Checker Method Implementations
//===----------------------------------------------------------------------===//

void EmbeddedDSLMonitorChecker::checkPostCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  // Generate generic event and let the monitor handle it
  auto event = createPostCallEvent(Call, C);
  Monitor->handleEvent(event, C);
}

void EmbeddedDSLMonitorChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  // Generate generic event and let the monitor handle it
  auto event = createPreCallEvent(Call, C);
  Monitor->handleEvent(event, C);
}

void EmbeddedDSLMonitorChecker::checkDeadSymbols(SymbolReaper &SR,
                                                 CheckerContext &C) const {
  // Generate events for all dead symbols
  ProgramStateRef State = C.getState();

  for (auto [Sym, Value] : State->get<GenericSymbolMap>()) {
    if (SR.isDead(Sym)) {
      // This symbol is dead and was tracked - report leak
      auto event = createDeadSymbolsEvent(Sym, C);
      Monitor->handleEvent(event, C);
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
