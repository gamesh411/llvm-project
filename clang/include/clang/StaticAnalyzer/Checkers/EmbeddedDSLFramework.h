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
//   - LTL parser and Büchi automaton generation
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
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/ImmutableMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

// Generic symbol-based GDM for symbol tracking
REGISTER_MAP_WITH_PROGRAMSTATE(GenericSymbolMap, clang::ento::SymbolRef,
                               std::string)
REGISTER_MAP_WITH_PROGRAMSTATE(LeakedSymbols, clang::ento::SymbolRef, bool)

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
class LTLAutomaton;
class LTLState;

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

//===----------------------------------------------------------------------===//
// LTL Parser and Büchi Automaton Generation
//===----------------------------------------------------------------------===//

// LTL State representation for Büchi automaton
class LTLState {
public:
  std::string StateID;
  std::set<std::string> AtomicPropositions;
  std::set<std::string> PendingFormulas;
  bool IsAccepting;
  std::string DiagnosticLabel;

  LTLState(const std::string &id, bool accepting = false)
      : StateID(id), IsAccepting(accepting) {}

  // Add atomic proposition to this state
  void addAtomicProposition(const std::string &prop) {
    AtomicPropositions.insert(prop);
  }

  // Add pending formula to this state
  void addPendingFormula(const std::string &formula) {
    PendingFormulas.insert(formula);
  }

  // Check if this state accepts a given set of atomic propositions
  bool accepts(const std::set<std::string> &propositions) const {
    for (const auto &required : AtomicPropositions) {
      if (propositions.find(required) == propositions.end()) {
        return false;
      }
    }
    return true;
  }
};

// Büchi Automaton for LTL monitoring
class LTLAutomaton {
private:
  std::vector<std::shared_ptr<LTLState>> States;
  std::shared_ptr<LTLState> InitialState;
  std::map<std::pair<std::shared_ptr<LTLState>, std::set<std::string>>,
           std::shared_ptr<LTLState>>
      Transitions;
  std::map<std::string, std::string> DiagnosticLabels;

public:
  LTLAutomaton() : InitialState(nullptr) {}

  // Add a state to the automaton
  void addState(std::shared_ptr<LTLState> state) {
    States.push_back(state);
    if (!InitialState) {
      InitialState = state;
    }
  }

  // Add a transition
  void addTransition(std::shared_ptr<LTLState> from,
                     const std::set<std::string> &propositions,
                     std::shared_ptr<LTLState> to) {
    Transitions[{from, propositions}] = to;
  }

  // Set diagnostic label for a state
  void setDiagnosticLabel(const std::string &stateID,
                          const std::string &label) {
    DiagnosticLabels[stateID] = label;
  }

  // Get current state after processing an event
  std::shared_ptr<LTLState>
  processEvent(std::shared_ptr<LTLState> currentState,
               const std::set<std::string> &propositions) {
    auto key = std::make_pair(currentState, propositions);
    auto it = Transitions.find(key);
    if (it != Transitions.end()) {
      return it->second;
    }
    return currentState; // Stay in current state if no transition
  }

  // Check if current state is accepting
  bool isAccepting(std::shared_ptr<LTLState> state) const {
    return state && state->IsAccepting;
  }

  // Get diagnostic label for a state
  std::string getDiagnosticLabel(std::shared_ptr<LTLState> state) const {
    if (!state)
      return "";
    auto it = DiagnosticLabels.find(state->StateID);
    return it != DiagnosticLabels.end() ? it->second : "";
  }

  // Get initial state
  std::shared_ptr<LTLState> getInitialState() const { return InitialState; }

  // Get all states
  const std::vector<std::shared_ptr<LTLState>> &getStates() const {
    return States;
  }
};

// LTL Parser for converting formula structure to Büchi automaton
class LTLParser {
private:
  std::shared_ptr<LTLFormulaNode> RootFormula;
  std::map<std::string, std::shared_ptr<LTLState>> StateMap;
  int StateCounter;

public:
  LTLParser(std::shared_ptr<LTLFormulaNode> formula)
      : RootFormula(formula), StateCounter(0) {}

  // Generate Büchi automaton from LTL formula
  std::unique_ptr<LTLAutomaton> generateAutomaton() {
    auto automaton = std::make_unique<LTLAutomaton>();

    if (!RootFormula) {
      return automaton;
    }

    // Create initial state with the root formula
    auto initialState = createState("q0", false);
    initialState->addPendingFormula(RootFormula->getStructuralInfo());

    automaton->addState(initialState);

    // Recursively build the automaton
    buildAutomatonStates(RootFormula, initialState, automaton.get());

    return automaton;
  }

private:
  // Create a new state
  std::shared_ptr<LTLState> createState(const std::string &prefix,
                                        bool accepting) {
    std::string stateID = prefix + "_" + std::to_string(StateCounter++);
    return std::make_shared<LTLState>(stateID, accepting);
  }

  // Recursively build automaton states from formula
  void buildAutomatonStates(std::shared_ptr<LTLFormulaNode> formula,
                            std::shared_ptr<LTLState> currentState,
                            LTLAutomaton *automaton) {
    if (!formula)
      return;

    switch (formula->Type) {
    case LTLNodeType::Atomic:
      buildAtomicState(formula, currentState, automaton);
      break;
    case LTLNodeType::And:
      buildAndState(formula, currentState, automaton);
      break;
    case LTLNodeType::Or:
      buildOrState(formula, currentState, automaton);
      break;
    case LTLNodeType::Not:
      buildNotState(formula, currentState, automaton);
      break;
    case LTLNodeType::Implies:
      buildImpliesState(formula, currentState, automaton);
      break;
    case LTLNodeType::Globally:
      buildGloballyState(formula, currentState, automaton);
      break;
    case LTLNodeType::Eventually:
      buildEventuallyState(formula, currentState, automaton);
      break;
    case LTLNodeType::Next:
      buildNextState(formula, currentState, automaton);
      break;
    default:
      // Handle other operators as needed
      break;
    }
  }

  // Build state for atomic proposition
  void buildAtomicState(std::shared_ptr<LTLFormulaNode> formula,
                        std::shared_ptr<LTLState> currentState,
                        LTLAutomaton *automaton) {
    auto atomicNode = std::static_pointer_cast<AtomicNode>(formula);
    std::string prop =
        atomicNode->FunctionName + "(" + atomicNode->Binding.SymbolName + ")";

    currentState->addAtomicProposition(prop);

    // Create accepting state for successful atomic proposition
    auto acceptingState = createState("accept", true);
    automaton->addState(acceptingState);

    // Add transition on the atomic proposition
    std::set<std::string> props = {prop};
    automaton->addTransition(currentState, props, acceptingState);

    // Set diagnostic label if available
    if (!formula->DiagnosticLabel.empty()) {
      automaton->setDiagnosticLabel(acceptingState->StateID,
                                    formula->DiagnosticLabel);
    }
  }

  // Build state for AND operator
  void buildAndState(std::shared_ptr<LTLFormulaNode> formula,
                     std::shared_ptr<LTLState> currentState,
                     LTLAutomaton *automaton) {
    // For AND, we need both children to be satisfied
    for (auto &child : formula->Children) {
      buildAutomatonStates(child, currentState, automaton);
    }
  }

  // Build state for OR operator
  void buildOrState(std::shared_ptr<LTLFormulaNode> formula,
                    std::shared_ptr<LTLState> currentState,
                    LTLAutomaton *automaton) {
    // For OR, we create separate paths for each child
    for (auto &child : formula->Children) {
      auto orState = createState("or", false);
      automaton->addState(orState);
      buildAutomatonStates(child, orState, automaton);

      // Add transition from current state to OR state
      std::set<std::string> empty;
      automaton->addTransition(currentState, empty, orState);
    }
  }

  // Build state for NOT operator
  void buildNotState(std::shared_ptr<LTLFormulaNode> formula,
                     std::shared_ptr<LTLState> currentState,
                     LTLAutomaton *automaton) {
    // For NOT, we create a state that accepts when the child is NOT satisfied
    if (!formula->Children.empty()) {
      auto notState = createState("not", false);
      automaton->addState(notState);

      // Build states for the negated formula
      buildAutomatonStates(formula->Children[0], notState, automaton);

      // Add transition from current state to NOT state
      std::set<std::string> empty;
      automaton->addTransition(currentState, empty, notState);
    }
  }

  // Build state for IMPLIES operator
  void buildImpliesState(std::shared_ptr<LTLFormulaNode> formula,
                         std::shared_ptr<LTLState> currentState,
                         LTLAutomaton *automaton) {
    // A → B is equivalent to ¬A ∨ B
    if (formula->Children.size() >= 2) {
      auto notA = std::make_shared<UnaryOpNode>(LTLNodeType::Not);
      notA->addChild(formula->Children[0]);

      auto orNode = std::make_shared<BinaryOpNode>(LTLNodeType::Or);
      orNode->addChild(notA);
      orNode->addChild(formula->Children[1]);

      buildAutomatonStates(orNode, currentState, automaton);
    }
  }

  // Build state for GLOBALLY operator
  void buildGloballyState(std::shared_ptr<LTLFormulaNode> formula,
                          std::shared_ptr<LTLState> currentState,
                          LTLAutomaton *automaton) {
    // G φ means φ must be true in all states
    if (!formula->Children.empty()) {
      auto globallyState = createState("globally", false);
      automaton->addState(globallyState);

      // Build states for the inner formula
      buildAutomatonStates(formula->Children[0], globallyState, automaton);

      // Add self-loop transition for globally
      std::set<std::string> empty;
      automaton->addTransition(globallyState, empty, globallyState);

      // Add transition from current state to globally state
      automaton->addTransition(currentState, empty, globallyState);
    }
  }

  // Build state for EVENTUALLY operator
  void buildEventuallyState(std::shared_ptr<LTLFormulaNode> formula,
                            std::shared_ptr<LTLState> currentState,
                            LTLAutomaton *automaton) {
    // F φ means φ must be true in some future state
    if (!formula->Children.empty()) {
      auto eventuallyState = createState("eventually", false);
      automaton->addState(eventuallyState);

      // Build states for the inner formula
      buildAutomatonStates(formula->Children[0], eventuallyState, automaton);

      // Add transition from current state to eventually state
      std::set<std::string> empty;
      automaton->addTransition(currentState, empty, eventuallyState);

      // Add self-loop transition for eventually
      automaton->addTransition(eventuallyState, empty, eventuallyState);
    }
  }

  // Build state for NEXT operator
  void buildNextState(std::shared_ptr<LTLFormulaNode> formula,
                      std::shared_ptr<LTLState> currentState,
                      LTLAutomaton *automaton) {
    // X φ means φ must be true in the next state
    if (!formula->Children.empty()) {
      auto nextState = createState("next", false);
      automaton->addState(nextState);

      // Build states for the inner formula
      buildAutomatonStates(formula->Children[0], nextState, automaton);

      // Add transition from current state to next state
      std::set<std::string> empty;
      automaton->addTransition(currentState, empty, nextState);
    }
  }
};

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

  // Generate Büchi automaton from the formula
  std::unique_ptr<LTLAutomaton> generateAutomaton() const {
    if (!Root) {
      return std::make_unique<LTLAutomaton>();
    }

    LTLParser parser(Root);
    return parser.generateAutomaton();
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
  std::unique_ptr<LTLAutomaton> Automaton;
  std::shared_ptr<LTLState> CurrentState;

public:
  MonitorAutomaton(std::unique_ptr<PropertyDefinition> prop,
                   const CheckerBase *Checker)
      : Handler(prop->createEventHandler(Checker)),
        PropertyName(prop->getPropertyName()),
        FormulaBuilder(prop->getFormulaBuilder()) {

    // Generate Büchi automaton from the formula
    Automaton = FormulaBuilder.generateAutomaton();
    CurrentState = Automaton->getInitialState();
  }

  void handleEvent(const GenericEvent &event, CheckerContext &C) {
    // Process event through the automaton
    if (Automaton && CurrentState) {
      std::set<std::string> propositions = extractPropositions(event);
      CurrentState = Automaton->processEvent(CurrentState, propositions);

      // Check for violations
      if (Automaton->isAccepting(CurrentState)) {
        std::string diagnostic = Automaton->getDiagnosticLabel(CurrentState);
        if (!diagnostic.empty()) {
          emitDiagnostic(diagnostic, event, C);
        }
      }
    }

    // Also handle through the traditional event handler
    Handler->handleEvent(event, C);
  }

  std::string getPropertyName() const { return PropertyName; }
  LTLFormulaBuilder getFormulaBuilder() const { return FormulaBuilder; }

private:
  // Extract atomic propositions from an event
  std::set<std::string> extractPropositions(const GenericEvent &event) {
    std::set<std::string> propositions;

    switch (event.Type) {
    case EventType::PostCall:
      propositions.insert(event.FunctionName + "(" + event.SymbolName + ")");
      break;
    case EventType::PreCall:
      propositions.insert(event.FunctionName + "(" + event.SymbolName + ")");
      break;
    case EventType::DeadSymbols:
      propositions.insert("dead(" + event.SymbolName + ")");
      break;
    }

    return propositions;
  }

  // Emit diagnostic for automaton-based violations
  void emitDiagnostic(const std::string &diagnostic, const GenericEvent &event,
                      CheckerContext &C) {
    // This would integrate with the existing diagnostic system
    // For now, we'll use the traditional handler's diagnostic system
  }
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
    if (!event.Symbol) {
      return;
    }

    // Generate error node
    ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
    if (!ErrorNode) {
      return;
    }

    auto R = std::make_unique<PathSensitiveBugReport>(
        getDoubleFreeBugType(), "memory freed twice (violates exactly-once)",
        ErrorNode);
    R->markInteresting(event.Symbol);
    C.emitReport(std::move(R));
  }

  void emitLeakDiagnostic(const GenericEvent &event, CheckerContext &C) {
    // Use the same pattern as MallocChecker - collect errors and emit at the
    // end
    if (!event.Symbol) {
      return;
    }

    // Mark the symbol as leaked in the state
    ProgramStateRef State = C.getState();
    State = State->set<LeakedSymbols>(event.Symbol, true);

    // Generate error node with the updated state
    ExplodedNode *ErrorNode = C.generateErrorNode(State);
    if (!ErrorNode) {
      return;
    }

    auto R = std::make_unique<PathSensitiveBugReport>(
        getLeakBugType(),
        "allocated memory is not freed (violates exactly-once)", ErrorNode);
    R->markInteresting(event.Symbol);
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

// Example: Mutex Lock/Unlock Property
// This demonstrates how the framework can be used for other temporal properties
class MutexLockUnlockProperty : public PropertyDefinition {
private:
  LTLFormulaBuilder FormulaBuilder;

public:
  MutexLockUnlockProperty() {
    // Build the LTL formula: G( lock(x) → F unlock(x) ∧ G( unlock(x) → G
    // ¬lock(x) ) ) "Globally, if a lock is acquired, it must eventually be
    // released, and once released, it cannot be acquired again until it is
    // released"

    auto lockCall = DSL::Call("lock", DSL::FirstParamVal("x"));
    auto unlockCall = DSL::Call("unlock", DSL::FirstParamVal("x"));

    auto eventuallyUnlock = DSL::F(unlockCall);
    eventuallyUnlock->withDiagnostic("Lock leak: acquired lock not released");

    auto unlockImpliesNoMoreLock =
        DSL::Implies(unlockCall, DSL::G(DSL::Not(lockCall)));
    unlockImpliesNoMoreLock->withDiagnostic(
        "Double lock: lock acquired multiple times");

    auto globallyNoMoreLock = DSL::G(unlockImpliesNoMoreLock);

    auto eventuallyUnlockAndNoMoreLock =
        DSL::And(eventuallyUnlock, globallyNoMoreLock);

    auto implication = DSL::Implies(lockCall, eventuallyUnlockAndNoMoreLock);

    auto globallyImplication = DSL::G(implication);
    globallyImplication->withDiagnostic("Mutex lock/unlock property violation");

    FormulaBuilder.setFormula(globallyImplication);
  }

  std::string getTemporalLogicFormula() const override {
    return "G( lock(x) → F unlock(x) ∧ G( unlock(x) → G ¬lock(x) ) )";
  }

  std::string getPropertyName() const override {
    return "mutex_lock_unlock_exactly_once";
  }

  LTLFormulaBuilder getFormulaBuilder() const override {
    return FormulaBuilder;
  }

  std::unique_ptr<EventHandler>
  createEventHandler(const CheckerBase *Checker) override {
    // For now, return the same handler - in a real implementation,
    // this would be a specialized MutexLockUnlockEventHandler
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
