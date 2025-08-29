//===-- EmbeddedDSLMonitorChecker.cpp --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// A baseline malloc/free checker that demonstrates tracking allocation state
// and checking it with CSA callbacks. This serves as a foundation for the
// temporal logic DSL implementation.
//
// Property:
//  For every successful malloc (non-null) there must be exactly one free(ptr)
//  where ptr equals the malloc return value.
// Reports:
//  - Leak (no matching free by symbol death)
//  - Double free (more than one matching free)
//===----------------------------------------------------------------------===//

#include "clang/AST/Decl.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <optional>

using namespace clang;
using namespace ento;

// Allocation state kind used by the program state map. Must be visible at
// global scope before registering the map trait.
enum class AllocState : unsigned {
  Unknown = 0,
  Acquired = 1,
  Released = 2,
  Handled = 3
};

// ProgramState trait must be outside of any namespace per macro contract and
// after the value type is declared.
REGISTER_MAP_WITH_PROGRAMSTATE(AllocSymMap, SymbolRef, AllocState)

namespace {

class EmbeddedDSLMonitorChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols> {
  const CallDescription MallocFn{CDM::CLibrary, {"malloc"}, 1};
  const CallDescription FreeFn{CDM::CLibrary, {"free"}, 1};

  const BugType LeakBT{this, "leak", "EmbeddedDSLMonitor",
                       /*SuppressOnSink=*/true};
  const BugType DoubleFreeBT{this, "double free", "EmbeddedDSLMonitor"};

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
};

void EmbeddedDSLMonitorChecker::checkPostCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  if (!MallocFn.matches(Call))
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym)
    return;

  // Track only possibly-non-null allocations.
  ConditionTruthVal IsNull = C.getConstraintManager().isNull(State, Sym);
  if (IsNull.isConstrainedTrue())
    return;

  if (!State->get<AllocSymMap>(Sym)) {
    C.addTransition(State->set<AllocSymMap>(Sym, AllocState::Acquired));
  }
}

void EmbeddedDSLMonitorChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  if (!FreeFn.matches(Call))
    return;

  ProgramStateRef State = C.getState();

  SymbolRef Sym = Call.getArgSVal(0).getAsSymbol();
  if (!Sym) {
    return;
  }

  // If the symbol is null, we are not warning, as we assume the allocation
  // failed, and calling free on null is ok.
  if (C.getConstraintManager().isNull(State, Sym).isConstrainedTrue())
    return;

  if (const AllocState *S = State->get<AllocSymMap>(Sym)) {
    switch (*S) {
    case AllocState::Unknown:
    case AllocState::Acquired:
      State = State->set<AllocSymMap>(Sym, AllocState::Released);
      C.addTransition(State);
      break;
    case AllocState::Released:
      C.emitReport(std::make_unique<PathSensitiveBugReport>(
          DoubleFreeBT, "memory freed twice (violates exactly-once)",
          C.generateErrorNode(State)));
      break;
    default:
      break;
    }
  }
}

void EmbeddedDSLMonitorChecker::checkDeadSymbols(SymbolReaper &SR,
                                                 CheckerContext &C) const {
  // If a memory address is becomes dead, and it is not freed, generate an
  // error. If the memory address is null, we are not warning, as we assume the
  // allocation failed, and so we are not leaking.

  ProgramStateRef State = C.getState();
  SmallVector<SymbolRef, 4> LeakedPossiblyNonNull;

  for (auto [Sym, S] : State->get<AllocSymMap>()) {
    if (!SR.isDead(Sym))
      continue;
    if (S == AllocState::Acquired) {
      ConditionTruthVal IsNull = C.getConstraintManager().isNull(State, Sym);
      const bool PossiblyNonNull = !IsNull.isConstrainedTrue();
      if (PossiblyNonNull) {
        LeakedPossiblyNonNull.push_back(Sym);
      }
    }
  }

  if (LeakedPossiblyNonNull.empty())
    return;

  // Create a single state transition that removes all leaked symbols
  ProgramStateRef CleanState = State;
  for (SymbolRef LS : LeakedPossiblyNonNull) {
    CleanState = CleanState->remove<AllocSymMap>(LS);
  }

  // Generate error node with the original state
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  // Emit reports for all leaked symbols
  for (SymbolRef LS : LeakedPossiblyNonNull) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        LeakBT, "allocated memory is not freed (violates exactly-once)", N);
    // Add the source range of the statement that caused the dead symbol, i.e.:
    // if there is an explicit return statement, mark that, or the end of the
    // block if there is no return statement.
    // auto *Stmt = N->getPreviousStmtForDiagnostics();
    // R->addRange(Stmt->getSourceRange());
    R->markInteresting(LS);
    C.emitReport(std::move(R));
  }

  // Add the clean state transition at the very end
  C.addTransition(CleanState, N);
}

} // end anonymous namespace

// Registration
void ento::registerEmbeddedDSLMonitor(CheckerManager &Mgr) {
  Mgr.registerChecker<EmbeddedDSLMonitorChecker>();
}

bool ento::shouldRegisterEmbeddedDSLMonitor(const CheckerManager &Mgr) {
  return true;
}
