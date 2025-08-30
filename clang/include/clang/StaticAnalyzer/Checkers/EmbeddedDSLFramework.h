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
// The framework supports:
//   - Generic event handling (preCall, postCall, deadSymbols)
//   - ASTMatchers integration for pattern matching
//   - SymbolRef-based GDM for symbol tracking
//   - Declarative property specification
//   - Reusable monitor automatons
//   - LTL formula structure with binding and diagnostic labeling
//
// Example LTL formula for malloc/free:
//   G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → G ¬free(x) ) )
//   "Globally, if malloc succeeds, eventually free it, and never free it again"
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
#include <functional>
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
// Embedded DSL Framework
//===----------------------------------------------------------------------===//

namespace dsl {

// Forward declarations
class MonitorAutomaton;
class EventHandler;
class PropertyDefinition;
class MallocFreeEventHandler;

// LTL Formula Node Types
enum class LTLNodeType {
  Atomic,     // Atomic proposition (malloc(x), free(x), etc.)
  And,        // Logical AND (∧)
  Or,         // Logical OR (∨)
  Not,        // Logical NOT (¬)
  Implies,    // Implication (→)
  Globally,   // Always (G)
  Eventually, // Eventually (F)
  Next,       // Next (X)
  Until,      // Until (U)
  Release     // Release (R)
};

// Symbol binding types
enum class BindingType {
  ReturnValue,    // Function return value
  FirstParameter, // First function parameter
  NthParameter,   // Nth function parameter
  Variable        // Direct variable reference
};

// Symbol binding information
struct SymbolBinding {
  BindingType Type;
  std::string SymbolName;
  int ParameterIndex; // For NthParameter

  SymbolBinding(BindingType t, const std::string &name, int paramIdx = 0)
      : Type(t), SymbolName(name), ParameterIndex(paramIdx) {}
};

// LTL Formula Node
class LTLFormulaNode {
public:
  LTLNodeType Type;
  std::string DiagnosticLabel;
  std::vector<std::shared_ptr<LTLFormulaNode>> Children;
  SymbolBinding Binding;
  std::string FunctionName; // For atomic propositions
  std::string Value;        // For atomic propositions

  LTLFormulaNode(LTLNodeType t, const std::string &label = "")
      : Type(t), DiagnosticLabel(label), Binding(BindingType::Variable, "") {}

  virtual ~LTLFormulaNode() = default;

  // Add child nodes
  void addChild(std::shared_ptr<LTLFormulaNode> child) {
    Children.push_back(child);
  }

  // Set diagnostic label
  LTLFormulaNode &withDiagnostic(const std::string &label) {
    DiagnosticLabel = label;
    return *this;
  }

  // Get formula as string
  virtual std::string toString() const = 0;

  // Get structural information for automaton generation
  virtual std::string getStructuralInfo() const = 0;
};

// Atomic Proposition Node
class AtomicNode : public LTLFormulaNode {
public:
  AtomicNode(const std::string &funcName, const SymbolBinding &binding,
             const std::string &label = "")
      : LTLFormulaNode(LTLNodeType::Atomic, label), Binding(binding),
        FunctionName(funcName) {}

  std::string toString() const override {
    std::string result = FunctionName + "(" + Binding.SymbolName + ")";
    if (!DiagnosticLabel.empty()) {
      result += " [" + DiagnosticLabel + "]";
    }
    return result;
  }

  std::string getStructuralInfo() const override {
    return "ATOMIC:" + FunctionName + ":" + Binding.SymbolName + ":" +
           std::to_string(static_cast<int>(Binding.Type));
  }

  SymbolBinding Binding;
  std::string FunctionName;
};

// Binary Operator Node
class BinaryOpNode : public LTLFormulaNode {
public:
  BinaryOpNode(LTLNodeType type, const std::string &label = "")
      : LTLFormulaNode(type, label) {}

  std::string toString() const override {
    std::string op;
    switch (Type) {
    case LTLNodeType::And:
      op = " ∧ ";
      break;
    case LTLNodeType::Or:
      op = " ∨ ";
      break;
    case LTLNodeType::Implies:
      op = " → ";
      break;
    case LTLNodeType::Until:
      op = " U ";
      break;
    case LTLNodeType::Release:
      op = " R ";
      break;
    default:
      op = " ? ";
      break;
    }

    std::string result = "(";
    for (size_t i = 0; i < Children.size(); ++i) {
      if (i > 0)
        result += op;
      result += Children[i]->toString();
    }
    result += ")";

    if (!DiagnosticLabel.empty()) {
      result += " [" + DiagnosticLabel + "]";
    }
    return result;
  }

  std::string getStructuralInfo() const override {
    std::string op;
    switch (Type) {
    case LTLNodeType::And:
      op = "AND";
      break;
    case LTLNodeType::Or:
      op = "OR";
      break;
    case LTLNodeType::Implies:
      op = "IMPLIES";
      break;
    case LTLNodeType::Until:
      op = "UNTIL";
      break;
    case LTLNodeType::Release:
      op = "RELEASE";
      break;
    default:
      op = "UNKNOWN";
      break;
    }

    std::string result = op + "(";
    for (size_t i = 0; i < Children.size(); ++i) {
      if (i > 0)
        result += ",";
      result += Children[i]->getStructuralInfo();
    }
    result += ")";
    return result;
  }
};

// Unary Operator Node
class UnaryOpNode : public LTLFormulaNode {
public:
  UnaryOpNode(LTLNodeType type, const std::string &label = "")
      : LTLFormulaNode(type, label) {}

  std::string toString() const override {
    std::string op;
    switch (Type) {
    case LTLNodeType::Not:
      op = "¬";
      break;
    case LTLNodeType::Globally:
      op = "G";
      break;
    case LTLNodeType::Eventually:
      op = "F";
      break;
    case LTLNodeType::Next:
      op = "X";
      break;
    default:
      op = "?";
      break;
    }

    std::string result = op + "(" + Children[0]->toString() + ")";
    if (!DiagnosticLabel.empty()) {
      result += " [" + DiagnosticLabel + "]";
    }
    return result;
  }

  std::string getStructuralInfo() const override {
    std::string op;
    switch (Type) {
    case LTLNodeType::Not:
      op = "NOT";
      break;
    case LTLNodeType::Globally:
      op = "GLOBALLY";
      break;
    case LTLNodeType::Eventually:
      op = "EVENTUALLY";
      break;
    case LTLNodeType::Next:
      op = "NEXT";
      break;
    default:
      op = "UNKNOWN";
      break;
    }

    return op + "(" + Children[0]->getStructuralInfo() + ")";
  }
};

// DSL Builder Functions
namespace DSL {

// Create atomic proposition for function call
inline std::shared_ptr<LTLFormulaNode> Call(const std::string &funcName,
                                            const SymbolBinding &binding) {
  return std::make_shared<AtomicNode>(funcName, binding);
}

// Create return value binding
inline SymbolBinding ReturnVal(const std::string &symbolName) {
  return SymbolBinding(BindingType::ReturnValue, symbolName);
}

// Create first parameter binding
inline SymbolBinding FirstParamVal(const std::string &symbolName) {
  return SymbolBinding(BindingType::FirstParameter, symbolName);
}

// Create nth parameter binding
inline SymbolBinding NthParamVal(const std::string &symbolName, int index) {
  return SymbolBinding(BindingType::NthParameter, symbolName, index);
}

// Create variable binding
inline SymbolBinding Var(const std::string &symbolName) {
  return SymbolBinding(BindingType::Variable, symbolName);
}

// Logical operators
inline std::shared_ptr<LTLFormulaNode>
And(std::shared_ptr<LTLFormulaNode> left,
    std::shared_ptr<LTLFormulaNode> right) {
  auto node = std::make_shared<BinaryOpNode>(LTLNodeType::And);
  node->addChild(left);
  node->addChild(right);
  return node;
}

inline std::shared_ptr<LTLFormulaNode>
Or(std::shared_ptr<LTLFormulaNode> left,
   std::shared_ptr<LTLFormulaNode> right) {
  auto node = std::make_shared<BinaryOpNode>(LTLNodeType::Or);
  node->addChild(left);
  node->addChild(right);
  return node;
}

inline std::shared_ptr<LTLFormulaNode>
Implies(std::shared_ptr<LTLFormulaNode> left,
        std::shared_ptr<LTLFormulaNode> right) {
  auto node = std::make_shared<BinaryOpNode>(LTLNodeType::Implies);
  node->addChild(left);
  node->addChild(right);
  return node;
}

// Temporal operators
inline std::shared_ptr<LTLFormulaNode>
G(std::shared_ptr<LTLFormulaNode> child) {
  auto node = std::make_shared<UnaryOpNode>(LTLNodeType::Globally);
  node->addChild(child);
  return node;
}

inline std::shared_ptr<LTLFormulaNode>
F(std::shared_ptr<LTLFormulaNode> child) {
  auto node = std::make_shared<UnaryOpNode>(LTLNodeType::Eventually);
  node->addChild(child);
  return node;
}

inline std::shared_ptr<LTLFormulaNode>
X(std::shared_ptr<LTLFormulaNode> child) {
  auto node = std::make_shared<UnaryOpNode>(LTLNodeType::Next);
  node->addChild(child);
  return node;
}

inline std::shared_ptr<LTLFormulaNode>
Not(std::shared_ptr<LTLFormulaNode> child) {
  auto node = std::make_shared<UnaryOpNode>(LTLNodeType::Not);
  node->addChild(child);
  return node;
}

// Utility functions
inline std::shared_ptr<LTLFormulaNode> NotNull(const SymbolBinding &binding) {
  // Create a special atomic node for null checks
  auto node = std::make_shared<AtomicNode>("not_null", binding);
  node->Value = "not_null";
  return node;
}

} // namespace DSL

// LTL Formula Builder
class LTLFormulaBuilder {
private:
  std::shared_ptr<LTLFormulaNode> Root;

public:
  LTLFormulaBuilder() : Root(nullptr) {}

  // Set the root formula
  void setFormula(std::shared_ptr<LTLFormulaNode> formula) { Root = formula; }

  // Get the complete formula as string
  std::string getFormulaString() const {
    return Root ? Root->toString() : "empty";
  }

  // Get structural information for automaton generation
  std::string getStructuralInfo() const {
    return Root ? Root->getStructuralInfo() : "EMPTY";
  }

  // Get all diagnostic labels
  std::vector<std::string> getDiagnosticLabels() const {
    std::vector<std::string> labels;
    collectLabels(Root, labels);
    return labels;
  }

  // Get all symbol bindings
  std::vector<SymbolBinding> getSymbolBindings() const {
    std::vector<SymbolBinding> bindings;
    collectBindings(Root, bindings);
    return bindings;
  }

  // Get all function names used in atomic propositions
  std::vector<std::string> getFunctionNames() const {
    std::vector<std::string> functions;
    collectFunctions(Root, functions);
    return functions;
  }

private:
  void collectLabels(std::shared_ptr<LTLFormulaNode> node,
                     std::vector<std::string> &labels) const {
    if (!node)
      return;

    if (!node->DiagnosticLabel.empty()) {
      labels.push_back(node->DiagnosticLabel);
    }

    for (auto &child : node->Children) {
      collectLabels(child, labels);
    }
  }

  void collectBindings(std::shared_ptr<LTLFormulaNode> node,
                       std::vector<SymbolBinding> &bindings) const {
    if (!node)
      return;

    if (node->Type == LTLNodeType::Atomic) {
      auto atomicNode = std::static_pointer_cast<AtomicNode>(node);
      bindings.push_back(atomicNode->Binding);
    }

    for (auto &child : node->Children) {
      collectBindings(child, bindings);
    }
  }

  void collectFunctions(std::shared_ptr<LTLFormulaNode> node,
                        std::vector<std::string> &functions) const {
    if (!node)
      return;

    if (node->Type == LTLNodeType::Atomic) {
      auto atomicNode = std::static_pointer_cast<AtomicNode>(node);
      functions.push_back(atomicNode->FunctionName);
    }

    for (auto &child : node->Children) {
      collectFunctions(child, functions);
    }
  }
};

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
  virtual LTLFormulaBuilder getFormulaBuilder() const = 0;
};

// Monitor automaton that handles generic events
class MonitorAutomaton {
  std::unique_ptr<EventHandler> Handler;
  std::string PropertyName;
  LTLFormulaBuilder FormulaBuilder;

public:
  MonitorAutomaton(std::unique_ptr<PropertyDefinition> prop,
                   const CheckerBase *Checker)
      : Handler(prop->createEventHandler(Checker)),
        PropertyName(prop->getPropertyName()),
        FormulaBuilder(prop->getFormulaBuilder()) {}

  void handleEvent(const GenericEvent &event, CheckerContext &C) {
    Handler->handleEvent(event, C);
  }

  std::string getPropertyName() const { return PropertyName; }
  LTLFormulaBuilder getFormulaBuilder() const { return FormulaBuilder; }
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
private:
  LTLFormulaBuilder FormulaBuilder;

public:
  MallocFreeProperty() {
    // Build the LTL formula: G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) →
    // G ¬free(x) ) )
    auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
    auto notNull = DSL::NotNull(DSL::Var("x"));
    auto mallocAndNotNull = DSL::And(mallocCall, notNull);

    auto freeCall = DSL::Call("free", DSL::FirstParamVal("x"));
    auto eventuallyFree = DSL::F(freeCall);
    eventuallyFree->withDiagnostic("Memory leak: allocated memory not freed");

    auto freeImpliesNoMoreFree =
        DSL::Implies(freeCall, DSL::G(DSL::Not(freeCall)));
    freeImpliesNoMoreFree->withDiagnostic(
        "Double free: memory freed multiple times");

    auto globallyNoMoreFree = DSL::G(freeImpliesNoMoreFree);

    auto eventuallyFreeAndNoMoreFree =
        DSL::And(eventuallyFree, globallyNoMoreFree);

    auto implication =
        DSL::Implies(mallocAndNotNull, eventuallyFreeAndNoMoreFree);

    auto globallyImplication = DSL::G(implication);
    globallyImplication->withDiagnostic("Memory management property violation");

    FormulaBuilder.setFormula(globallyImplication);
  }

  std::string getTemporalLogicFormula() const override {
    return "G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → G ¬free(x) ) )";
  }

  std::string getPropertyName() const override {
    return "malloc_free_exactly_once";
  }

  LTLFormulaBuilder getFormulaBuilder() const override {
    return FormulaBuilder;
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
