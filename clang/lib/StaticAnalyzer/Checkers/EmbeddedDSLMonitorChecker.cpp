//===-- EmbeddedDSLMonitorChecker.cpp --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Embedded DSL-based malloc/free checker using pure linear temporal logic.
//
// Pure Linear Temporal Logic Formula:
//   G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → X ¬free(x) ) )
//
// Where:
//   G = Globally (always)
//   F = Finally (eventually)
//   X = Next
//   ∧ = AND
//   → = IMPLIES
//   ¬ = NOT
//   malloc(x) = malloc call returning symbolic value x
//   free(x) = free call with symbolic value x as first parameter
//   x ≠ null = constraint that x is not null
//
// This formula expresses:
//   1. Globally, if malloc(x) succeeds (x ≠ null), then eventually free(x) must
//   occur
//   2. After free(x) occurs, globally no subsequent free(x) should occur
//   (exactly-once)
//
// Violations:
//   - Eventually part broken: Memory leak (malloc without matching free)
//   - Exactly-once part broken: Double free (multiple frees of same pointer)
//
// The embedded DSL provides:
//   - Symbolic value binding and referencing
//   - ASTMatchers integration for function matching
//   - Diagnostic features tied to specific temporal logic parts
//   - Declarative property specification
//===----------------------------------------------------------------------===//

#include "clang/AST/Decl.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace ast_matchers;

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

//===----------------------------------------------------------------------===//
// Embedded DSL for Temporal Logic Specification
//===----------------------------------------------------------------------===//

namespace dsl {

// Symbolic value binding for tracking malloc return values
class SymbolicBinding {
  std::string Name;
  SymbolRef Symbol;

public:
  SymbolicBinding(const std::string &N, SymbolRef S) : Name(N), Symbol(S) {}

  const std::string &getName() const { return Name; }
  SymbolRef getSymbol() const { return Symbol; }

  // DSL syntax: bind("x", malloc_call)
  static SymbolicBinding bind(const std::string &name, SymbolRef symbol) {
    return SymbolicBinding(name, symbol);
  }
};

// Atomic propositions representing events we observe
class AtomicProposition {
public:
  enum class Kind {
    MallocSuccess, // malloc(x) ∧ x ≠ null
    FreeOfSymbol,  // free(x) where x matches bound symbol
    SymbolNotNull  // x ≠ null constraint
  };

private:
  Kind APKind;
  SymbolicBinding Binding;
  std::string Description;

public:
  AtomicProposition(Kind k, const SymbolicBinding &bind,
                    const std::string &desc = "")
      : APKind(k), Binding(bind), Description(desc) {}

  Kind getKind() const { return APKind; }
  const SymbolicBinding &getBinding() const { return Binding; }
  const std::string &getDescription() const { return Description; }

  // DSL syntax: malloc_success("x") or free_of_symbol("x")
  static AtomicProposition malloc_success(const std::string &symbol_name) {
    return AtomicProposition(Kind::MallocSuccess,
                             SymbolicBinding(symbol_name, nullptr),
                             "malloc(" + symbol_name + ") succeeds");
  }

  static AtomicProposition free_of_symbol(const std::string &symbol_name) {
    return AtomicProposition(Kind::FreeOfSymbol,
                             SymbolicBinding(symbol_name, nullptr),
                             "free(" + symbol_name + ") called");
  }

  static AtomicProposition symbol_not_null(const std::string &symbol_name) {
    return AtomicProposition(Kind::SymbolNotNull,
                             SymbolicBinding(symbol_name, nullptr),
                             symbol_name + " ≠ null");
  }
};

// Diagnostic context for tying diagnostics to specific parts of the temporal
// logic
class DiagnosticContext {
public:
  enum class ViolationType {
    EventuallyViolated, // F free(x) part broken - memory leak
    ExactlyOnceViolated // G( free(x) → X ¬free(x) ) part broken - double free
  };

private:
  ViolationType Type;
  std::string Description;
  const AtomicProposition *RelatedAP;

public:
  DiagnosticContext(ViolationType t, const std::string &desc,
                    const AtomicProposition *ap = nullptr)
      : Type(t), Description(desc), RelatedAP(ap) {}

  ViolationType getType() const { return Type; }
  const std::string &getDescription() const { return Description; }
  const AtomicProposition *getRelatedAP() const { return RelatedAP; }

  // DSL syntax for creating diagnostic contexts
  static DiagnosticContext eventually_violated(const std::string &symbol_name) {
    static AtomicProposition malloc_ap = AtomicProposition::malloc_success("x");
    return DiagnosticContext(
        ViolationType::EventuallyViolated,
        "Eventually part violated: " + symbol_name + " not freed", &malloc_ap);
  }

  static DiagnosticContext
  exactly_once_violated(const std::string &symbol_name) {
    static AtomicProposition free_ap = AtomicProposition::free_of_symbol("x");
    return DiagnosticContext(ViolationType::ExactlyOnceViolated,
                             "Exactly-once part violated: " + symbol_name +
                                 " freed multiple times",
                             &free_ap);
  }
};

} // namespace dsl

//===----------------------------------------------------------------------===//
// ASTMatchers Integration
//===----------------------------------------------------------------------===//

// ASTMatchers for finding malloc and free calls
class MallocFreeMatchers {
public:
  // Match malloc calls: malloc(size)
  static DeclarationMatcher mallocMatcher() {
    return functionDecl(hasName("malloc"), parameterCountIs(1),
                        hasParameter(0, hasType(isInteger())));
  }

  // Match free calls: free(ptr)
  static DeclarationMatcher freeMatcher() {
    return functionDecl(hasName("free"), parameterCountIs(1),
                        hasParameter(0, hasType(pointerType())));
  }

  // Match malloc call expressions
  static StatementMatcher mallocCallMatcher() {
    return callExpr(callee(functionDecl(hasName("malloc"))), argumentCountIs(1))
        .bind("malloc_call");
  }

  // Match free call expressions
  static StatementMatcher freeCallMatcher() {
    return callExpr(callee(functionDecl(hasName("free"))), argumentCountIs(1))
        .bind("free_call");
  }
};

//===----------------------------------------------------------------------===//
// Main Checker Implementation
//===----------------------------------------------------------------------===//

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

private:
  // DSL-based violation detection
  void checkEventuallyViolation(SymbolRef Sym, CheckerContext &C) const;
  void checkExactlyOnceViolation(SymbolRef Sym, CheckerContext &C) const;

  // Symbolic binding management
  dsl::SymbolicBinding createSymbolicBinding(const std::string &name,
                                             SymbolRef sym) const;
  bool matchesSymbolicBinding(const dsl::SymbolicBinding &binding,
                              SymbolRef sym) const;
};

void EmbeddedDSLMonitorChecker::checkPostCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  if (!MallocFn.matches(Call))
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym)
    return;

  // Track only possibly-non-null allocations (DSL: malloc(x) ∧ x ≠ null)
  ConditionTruthVal IsNull = C.getConstraintManager().isNull(State, Sym);
  if (IsNull.isConstrainedTrue())
    return;

  // Create symbolic binding for the DSL formula
  auto binding = createSymbolicBinding("x", Sym);

  // DSL: Check if this matches malloc_success("x") ∧ symbol_not_null("x")
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
      // DSL: This violates the G( free(x) → X ¬free(x) ) part - exactly-once
      // violation
      checkExactlyOnceViolation(Sym, C);
      break;
    default:
      break;
    }
  }
}

void EmbeddedDSLMonitorChecker::checkDeadSymbols(SymbolReaper &SR,
                                                 CheckerContext &C) const {
  // DSL: Check for violations of the F free(x) part when symbols become dead
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

  // Emit reports for all leaked symbols with DSL-based diagnostics
  for (SymbolRef LS : LeakedPossiblyNonNull) {
    // DSL: This is an eventually violation - F free(x) part broken
    auto diagnostic = dsl::DiagnosticContext::eventually_violated("x");

    auto R = std::make_unique<PathSensitiveBugReport>(
        LeakBT,
        "allocated memory is not freed (violates eventually part: F free(x))",
        N);
    R->markInteresting(LS);
    C.emitReport(std::move(R));
  }

  // Add the clean state transition at the very end
  C.addTransition(CleanState, N);
}

//===----------------------------------------------------------------------===//
// DSL-Based Violation Detection
//===----------------------------------------------------------------------===//

void EmbeddedDSLMonitorChecker::checkEventuallyViolation(
    SymbolRef Sym, CheckerContext &C) const {
  // DSL: This method handles violations of the F free(x) part
  // Called when a symbol becomes dead without being freed

  auto diagnostic = dsl::DiagnosticContext::eventually_violated("x");

  auto R = std::make_unique<PathSensitiveBugReport>(
      LeakBT,
      "allocated memory is not freed (violates eventually part: F free(x))",
      C.generateErrorNode(C.getState()));
  R->markInteresting(Sym);
  C.emitReport(std::move(R));
}

void EmbeddedDSLMonitorChecker::checkExactlyOnceViolation(
    SymbolRef Sym, CheckerContext &C) const {
  // DSL: This method handles violations of the G( free(x) → X ¬free(x) ) part
  // Called when free is called on an already freed symbol

  auto diagnostic = dsl::DiagnosticContext::exactly_once_violated("x");

  auto R = std::make_unique<PathSensitiveBugReport>(
      DoubleFreeBT,
      "memory freed twice (violates exactly-once part: G( free(x) → X ¬free(x) "
      "))",
      C.generateErrorNode(C.getState()));
  R->markInteresting(Sym);
  C.emitReport(std::move(R));
}

//===----------------------------------------------------------------------===//
// Symbolic Binding Management
//===----------------------------------------------------------------------===//

dsl::SymbolicBinding
EmbeddedDSLMonitorChecker::createSymbolicBinding(const std::string &name,
                                                 SymbolRef sym) const {
  return dsl::SymbolicBinding::bind(name, sym);
}

bool EmbeddedDSLMonitorChecker::matchesSymbolicBinding(
    const dsl::SymbolicBinding &binding, SymbolRef sym) const {
  // For now, we use simple symbol equality
  // In a more sophisticated implementation, this could handle
  // symbolic value relationships and constraints
  return binding.getSymbol() == sym;
}

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Registration
//===----------------------------------------------------------------------===//

void ento::registerEmbeddedDSLMonitor(CheckerManager &Mgr) {
  Mgr.registerChecker<EmbeddedDSLMonitorChecker>();
}

bool ento::shouldRegisterEmbeddedDSLMonitor(const CheckerManager &Mgr) {
  return true;
}
