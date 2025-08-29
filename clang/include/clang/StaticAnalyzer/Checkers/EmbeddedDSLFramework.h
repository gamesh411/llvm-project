//===--- EmbeddedDSLFramework.h - Embedded DSL Framework for CSA ----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines the embedded DSL framework for the Clang Static Analyzer.
// It provides a reusable framework for implementing temporal logic-based
// static analysis properties using a monitor automaton approach.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H
#define LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/ImmutableMap.h"
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// Generic symbol-based GDM for symbol tracking
REGISTER_MAP_WITH_PROGRAMSTATE(GenericSymbolMap, clang::ento::SymbolRef,
                               std::string)

namespace clang {
namespace ento {

// Generic events that checkers can emit
enum class EventType {
  PreCall,    // Function call about to happen
  PostCall,   // Function call just completed
  DeadSymbols // Symbols are becoming dead
};

// Generic event structure
struct GenericEvent {
  EventType Type;
  std::string FunctionName;
  std::string SymbolName;
  SymbolRef Symbol;
  const CallEvent *Call;

  GenericEvent(EventType t, const std::string &fn, const std::string &sn,
               SymbolRef sym = nullptr, const CallEvent *call = nullptr)
      : Type(t), FunctionName(fn), SymbolName(sn), Symbol(sym), Call(call) {}
};

//===----------------------------------------------------------------------===//
// Dynamic DSL Framework
//===----------------------------------------------------------------------===//

namespace dsl {

// Forward declarations
class MonitorAutomaton;
class EventHandler;
class PropertyDefinition;
class MallocFreeEventHandler;

// Generic event handler interface
class EventHandler {
public:
  virtual ~EventHandler() = default;
  virtual void handleEvent(const GenericEvent &event, CheckerContext &C) = 0;
  virtual std::string getDescription() const = 0;
};

// Property definition interface
class PropertyDefinition {
public:
  virtual ~PropertyDefinition() = default;
  virtual std::unique_ptr<EventHandler>
  createEventHandler(const CheckerBase *Checker) = 0;
  virtual std::string getTemporalLogicFormula() const = 0;
  virtual std::string getPropertyName() const = 0;
};

// Monitor automaton that handles generic events
class MonitorAutomaton {
  std::unique_ptr<EventHandler> Handler;
  std::string PropertyName;

public:
  MonitorAutomaton(std::unique_ptr<PropertyDefinition> prop,
                   const CheckerBase *Checker)
      : Handler(prop->createEventHandler(Checker)),
        PropertyName(prop->getPropertyName()) {}

  void handleEvent(const GenericEvent &event, CheckerContext &C) {
    Handler->handleEvent(event, C);
  }

  std::string getPropertyName() const { return PropertyName; }
};

// Generic ASTMatchers wrapper
class PatternMatcher {
public:
  static bool matchesMallocCall(const CallEvent &Call) {
    return Call.getCalleeIdentifier() &&
           Call.getCalleeIdentifier()->getName() == "malloc";
  }

  static bool matchesFreeCall(const CallEvent &Call) {
    return Call.getCalleeIdentifier() &&
           Call.getCalleeIdentifier()->getName() == "free";
  }

  static bool isNotNull(SymbolRef Sym, CheckerContext &C) {
    ProgramStateRef State = C.getState();
    ConditionTruthVal IsNull = C.getConstraintManager().isNull(State, Sym);
    return !IsNull.isConstrainedTrue();
  }
};

// Generic symbol tracking via symbol-based GDM
class SymbolTracker {
public:
  static void trackSymbol(ProgramStateRef State, SymbolRef sym,
                          const std::string &value, CheckerContext &C) {
    C.addTransition(State->set<GenericSymbolMap>(sym, value));
  }

  static std::string getSymbolValue(ProgramStateRef State, SymbolRef sym) {
    if (const std::string *value = State->get<GenericSymbolMap>(sym)) {
      return *value;
    }
    return "";
  }

  static void removeSymbol(ProgramStateRef State, SymbolRef sym,
                           CheckerContext &C) {
    C.addTransition(State->remove<GenericSymbolMap>(sym));
  }

  static bool hasSymbol(ProgramStateRef State, SymbolRef sym) {
    return State->get<GenericSymbolMap>(sym) != nullptr;
  }
};

// Malloc/Free Event Handler
class MallocFreeEventHandler : public EventHandler {
private:
  const CheckerBase *Checker;

public:
  MallocFreeEventHandler(const CheckerBase *C) : Checker(C) {}

  std::string getDescription() const override {
    return "Monitors malloc/free exactly-once property";
  }

  void handleEvent(const GenericEvent &event, CheckerContext &C) override {
    ProgramStateRef State = C.getState();

    switch (event.Type) {
    case EventType::PostCall:
      if (PatternMatcher::matchesMallocCall(*event.Call)) {
        handleMallocPostCall(event, C);
      }
      break;

    case EventType::PreCall:
      if (PatternMatcher::matchesFreeCall(*event.Call)) {
        handleFreePreCall(event, C);
      }
      break;

    case EventType::DeadSymbols:
      handleDeadSymbols(event, C);
      break;
    }
  }

private:
  void handleMallocPostCall(const GenericEvent &event, CheckerContext &C) {
    ProgramStateRef State = C.getState();
    SymbolRef Sym = event.Symbol;

    if (!Sym || !PatternMatcher::isNotNull(Sym, C))
      return;

    // Track the allocation
    SymbolTracker::trackSymbol(State, Sym, "acquired", C);
  }

  void handleFreePreCall(const GenericEvent &event, CheckerContext &C) {
    ProgramStateRef State = C.getState();
    SymbolRef Sym = event.Symbol;

    if (!Sym)
      return;

    if (SymbolTracker::hasSymbol(State, Sym)) {
      std::string status = SymbolTracker::getSymbolValue(State, Sym);

      if (status == "acquired") {
        // First free - mark as released
        SymbolTracker::trackSymbol(State, Sym, "released", C);
      } else if (status == "released") {
        // Double free - emit diagnostic
        emitDoubleFreeDiagnostic(event, C);
      }
    }
  }

  void handleDeadSymbols(const GenericEvent &event, CheckerContext &C) {
    ProgramStateRef State = C.getState();
    SymbolRef Sym = event.Symbol;

    if (Sym && SymbolTracker::hasSymbol(State, Sym)) {
      std::string status = SymbolTracker::getSymbolValue(State, Sym);

      if (status == "acquired") {
        // Memory leak - emit diagnostic
        emitLeakDiagnostic(event, C);
        SymbolTracker::removeSymbol(State, Sym, C);
      }
    }
  }

  void emitDoubleFreeDiagnostic(const GenericEvent &event, CheckerContext &C) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        getDoubleFreeBugType(), "memory freed twice (violates exactly-once)",
        C.generateErrorNode(C.getState()));
    if (event.Symbol) {
      R->markInteresting(event.Symbol);
    }
    C.emitReport(std::move(R));
  }

  void emitLeakDiagnostic(const GenericEvent &event, CheckerContext &C) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        getLeakBugType(),
        "allocated memory is not freed (violates exactly-once)",
        C.generateErrorNode(C.getState()));
    if (event.Symbol) {
      R->markInteresting(event.Symbol);
    }
    C.emitReport(std::move(R));
  }

  const BugType &getDoubleFreeBugType() const {
    static const BugType BT{Checker, "double free", "EmbeddedDSLMonitor"};
    return BT;
  }

  const BugType &getLeakBugType() const {
    static const BugType BT{Checker, "leak", "EmbeddedDSLMonitor"};
    return BT;
  }
};

// Malloc/Free Property Implementation
class MallocFreeProperty : public PropertyDefinition {
public:
  std::string getTemporalLogicFormula() const override {
    return "G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → X ¬free(x) ) )";
  }

  std::string getPropertyName() const override {
    return "malloc_free_exactly_once";
  }

  std::unique_ptr<EventHandler>
  createEventHandler(const CheckerBase *Checker) override {
    return std::make_unique<MallocFreeEventHandler>(Checker);
  }
};

} // namespace dsl

} // namespace ento
} // namespace clang

// LLVM traits for std::string values
template <> struct llvm::FoldingSetTrait<std::string> {
  static inline void Profile(const std::string &X, llvm::FoldingSetNodeID &ID) {
    ID.AddString(X);
  }
};

#endif // LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H
