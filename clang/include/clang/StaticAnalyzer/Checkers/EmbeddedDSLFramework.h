// Embedded DSL Framework for Temporal Logic-Based Static Analysis
// This framework provides a domain-specific language for defining temporal
// logic properties and automatically generating monitor automatons for
// violation detection.

#ifndef LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H
#define LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H

#include "clang/AST/Decl.h"
#include "clang/AST/DeclBase.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <cstdlib>

// Generic symbol state for any temporal property
enum class SymbolState {
  Uninitialized, // Symbol not yet processed
  Active,        // Symbol is in active state
  Inactive,      // Symbol is in inactive state
  Violated,      // Symbol violates the property
  Invalid        // Invalid state
};

// Generic symbol usage context in temporal formulas
enum class SymbolContext {
  Creation,    // Symbol is created (return value, acquisition)
  Destruction, // Symbol is destroyed (parameter, release)
  Validation,  // Symbol is validated (condition check)
  Temporal,    // Symbol appears in temporal operators (F, G, U, etc.)
  CrossContext // Symbol appears in multiple contexts
};

// State trait registrations
REGISTER_MAP_WITH_PROGRAMSTATE(GenericSymbolMap, clang::ento::SymbolRef,
                               std::string)
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolStates, clang::ento::SymbolRef,
                               SymbolState)
REGISTER_MAP_WITH_PROGRAMSTATE(CrossContextSymbolMap, std::string,
                               clang::ento::SymbolRef)
// Symbols that should report leak at function end (to place diag at closing brace)
REGISTER_SET_WITH_PROGRAMSTATE(PendingLeakSet, clang::ento::SymbolRef)
// Symbols that became dead along a path; finalize at EndFunction for brace location
REGISTER_SET_WITH_PROGRAMSTATE(FunctionEndLeakSet, clang::ento::SymbolRef)

namespace llvm {
template <> struct FoldingSetTrait<std::string> {
  static void Profile(const std::string &X, FoldingSetNodeID &ID) {
    ID.AddString(X);
  }
};
} // namespace llvm

namespace clang {
namespace ento {
namespace dsl {
// Debug helper (opt-in via environment variable EDSL_DEBUG)
static inline bool edslDebugEnabled() {
  static int Initialized = 0;
  static bool Enabled = false;
  if (!Initialized) {
    Enabled = std::getenv("EDSL_DEBUG") != nullptr;
    Initialized = 1;
  }
  return Enabled;
}


// Forward declarations
class LTLFormulaNode;
class LTLState;
class LTLAutomaton;
class LTLParser;
class AutomaticSymbolTracker;

// LTL formula node types
enum class LTLNodeType {
  Atomic,     // Atomic proposition (function call, variable)
  And,        // Logical AND
  Or,         // Logical OR
  Not,        // Logical NOT
  Implies,    // Logical implication
  Globally,   // Always (G)
  Eventually, // Eventually (F)
  Next,       // Next (X)
  Until,      // Until (U)
  Release     // Release (R)
};

// Symbol binding types for DSL
enum class BindingType {
  ReturnValue,    // Function return value
  FirstParameter, // First function parameter
  NthParameter,   // Nth function parameter
  Variable        // General variable
};

// Symbol binding information
struct SymbolBinding {
  BindingType Type;
  std::string SymbolName;
  int ParameterIndex; // For NthParameter

  SymbolBinding(BindingType t, const std::string &name, int index = 0)
      : Type(t), SymbolName(name), ParameterIndex(index) {}
};

// Symbol tracking information derived from formula analysis
struct SymbolTrackingInfo {
  std::string SymbolName;
  std::set<SymbolContext> Contexts;
  std::set<std::string> Functions; // Functions that operate on this symbol
  bool IsTemporallyTracked;        // Appears in temporal operators
  bool IsCrossContext;             // Appears in multiple contexts
  std::string
      PrimaryFunction; // Main function for this symbol (e.g., "malloc" for "x")

  SymbolTrackingInfo(const std::string &name)
      : SymbolName(name), IsTemporallyTracked(false), IsCrossContext(false) {}
};

// Base class for LTL formula nodes
class LTLFormulaNode {
public:
  LTLNodeType Type;
  std::string DiagnosticLabel;
  std::vector<std::shared_ptr<LTLFormulaNode>> Children;
  SymbolBinding Binding;    // Member that needed explicit initialization
  std::string FunctionName; // For atomic propositions
  std::string Value;        // For atomic propositions
  // Stable node identity for mapping into external monitors (e.g., SPOT)
  int NodeID;
  // Parent pointer to support ancestor-based diagnostic selection
  LTLFormulaNode *Parent;

  LTLFormulaNode(LTLNodeType t, const std::string &label = "")
      : Type(t), DiagnosticLabel(label), Children(),
        Binding(BindingType::Variable, ""), FunctionName(), Value(),
        NodeID(nextNodeID()), Parent(nullptr) {}

  virtual ~LTLFormulaNode() = default;

  // Convert node to string representation
  virtual std::string toString() const = 0;

  // Get structural information for automaton generation
  virtual std::string getStructuralInfo() const = 0;

  // Add diagnostic label to this node
  LTLFormulaNode *withDiagnostic(const std::string &label) {
    DiagnosticLabel = label;
    return this;
  }

  // Utilities
  static int nextNodeID() {
    static int Counter = 0;
    return ++Counter;
  }
};

// Atomic proposition node (function calls, variables)
class AtomicNode : public LTLFormulaNode {
public:
  AtomicNode(const std::string &funcName, const SymbolBinding &binding,
             const std::string &value = "")
      : LTLFormulaNode(LTLNodeType::Atomic) {
    FunctionName = funcName;
    Binding = binding;
    Value = value;
  }

  std::string toString() const override {
    std::string result;
    if (!FunctionName.empty()) {
      result = FunctionName + "(" + Binding.SymbolName + ")";
    } else {
      result = Binding.SymbolName;
    }

    if (!DiagnosticLabel.empty()) {
      result += " [" + DiagnosticLabel + "]";
    }
    return result;
  }

  std::string getStructuralInfo() const override {
    return "Atomic[" + FunctionName + "(" + Binding.SymbolName + ")]";
  }
};

// Binary operator node (And, Or, Implies, Until, Release)
class BinaryOpNode : public LTLFormulaNode {
public:
  BinaryOpNode(LTLNodeType type, std::shared_ptr<LTLFormulaNode> left,
               std::shared_ptr<LTLFormulaNode> right)
      : LTLFormulaNode(type) {
    Children.push_back(left);
    Children.push_back(right);
    if (left)
      left->Parent = this;
    if (right)
      right->Parent = this;
  }

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
    }
    std::string result =
        "(" + Children[0]->toString() + op + Children[1]->toString() + ")";

    if (!DiagnosticLabel.empty()) {
      result += " [" + DiagnosticLabel + "]";
    }
    return result;
  }

  std::string getStructuralInfo() const override {
    std::string op;
    switch (Type) {
    case LTLNodeType::And:
      op = "And";
      break;
    case LTLNodeType::Or:
      op = "Or";
      break;
    case LTLNodeType::Implies:
      op = "Implies";
      break;
    case LTLNodeType::Until:
      op = "Until";
      break;
    case LTLNodeType::Release:
      op = "Release";
      break;
    default:
      op = "BinaryOp";
    }
    return op + "(" + Children[0]->getStructuralInfo() + ", " +
           Children[1]->getStructuralInfo() + ")";
  }
};

// Unary operator node (Not, Globally, Eventually, Next)
class UnaryOpNode : public LTLFormulaNode {
public:
  UnaryOpNode(LTLNodeType type, std::shared_ptr<LTLFormulaNode> child)
      : LTLFormulaNode(type) {
    Children.push_back(child);
    if (child)
      child->Parent = this;
  }

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
      op = "Not";
      break;
    case LTLNodeType::Globally:
      op = "Globally";
      break;
    case LTLNodeType::Eventually:
      op = "Eventually";
      break;
    case LTLNodeType::Next:
      op = "Next";
      break;
    default:
      op = "UnaryOp";
    }
    return op + "(" + Children[0]->getStructuralInfo() + ")";
  }
};

// DSL builder functions for constructing LTL formulas
namespace DSL {
inline std::shared_ptr<LTLFormulaNode> Call(const std::string &funcName,
                                            const SymbolBinding &binding) {
  return std::make_shared<AtomicNode>(funcName, binding);
}

inline std::shared_ptr<LTLFormulaNode>
ReturnVal(const std::string &symbolName) {
  return std::make_shared<AtomicNode>(
      "", SymbolBinding(BindingType::ReturnValue, symbolName));
}

inline std::shared_ptr<LTLFormulaNode>
FirstParamVal(const std::string &symbolName) {
  return std::make_shared<AtomicNode>(
      "", SymbolBinding(BindingType::FirstParameter, symbolName));
}

inline std::shared_ptr<LTLFormulaNode>
NthParamVal(const std::string &symbolName, int index) {
  return std::make_shared<AtomicNode>(
      "", SymbolBinding(BindingType::NthParameter, symbolName, index));
}

inline std::shared_ptr<LTLFormulaNode> Var(const std::string &symbolName) {
  return std::make_shared<AtomicNode>(
      "", SymbolBinding(BindingType::Variable, symbolName));
}

inline std::shared_ptr<LTLFormulaNode>
And(std::shared_ptr<LTLFormulaNode> left,
    std::shared_ptr<LTLFormulaNode> right) {
  return std::make_shared<BinaryOpNode>(LTLNodeType::And, left, right);
}

inline std::shared_ptr<LTLFormulaNode>
Or(std::shared_ptr<LTLFormulaNode> left,
   std::shared_ptr<LTLFormulaNode> right) {
  return std::make_shared<BinaryOpNode>(LTLNodeType::Or, left, right);
}

inline std::shared_ptr<LTLFormulaNode>
Implies(std::shared_ptr<LTLFormulaNode> left,
        std::shared_ptr<LTLFormulaNode> right) {
  return std::make_shared<BinaryOpNode>(LTLNodeType::Implies, left, right);
}

inline std::shared_ptr<LTLFormulaNode>
G(std::shared_ptr<LTLFormulaNode> child) {
  return std::make_shared<UnaryOpNode>(LTLNodeType::Globally, child);
}

inline std::shared_ptr<LTLFormulaNode>
F(std::shared_ptr<LTLFormulaNode> child) {
  return std::make_shared<UnaryOpNode>(LTLNodeType::Eventually, child);
}

inline std::shared_ptr<LTLFormulaNode>
X(std::shared_ptr<LTLFormulaNode> child) {
  return std::make_shared<UnaryOpNode>(LTLNodeType::Next, child);
}

inline std::shared_ptr<LTLFormulaNode>
Not(std::shared_ptr<LTLFormulaNode> child) {
  return std::make_shared<UnaryOpNode>(LTLNodeType::Not, child);
}

inline std::shared_ptr<LTLFormulaNode>
NotNull(std::shared_ptr<LTLFormulaNode> var) {
  return Not(Var(var->Binding.SymbolName));
}

// Predicate atom: symbol is provably non-null along the current path
inline std::shared_ptr<LTLFormulaNode>
IsNonNull(const std::string &symbolName) {
  auto node = std::make_shared<AtomicNode>("__isnonnull", SymbolBinding(BindingType::Variable, symbolName));
  return node;
}

inline std::shared_ptr<LTLFormulaNode>
IsNonNull(std::shared_ptr<LTLFormulaNode> var) {
  return IsNonNull(var->Binding.SymbolName);
}
} // namespace DSL

// General Symbolic Value Persistence System
// This system ensures that symbolic values are consistently shared across
// different contexts and program points, using GDM for cross-context symbol
// storage.

// Symbol usage patterns in formulas
enum class SymbolUsagePattern {
  SingleOccurrence,     // Symbol appears only once
  MultipleOccurrences,  // Symbol appears multiple times in same context
  CrossTemporalContext, // Symbol appears in different temporal contexts (G, F,
                        // etc.)
  CrossSubformula,  // Symbol appears in different subformulas of same context
  CrossProgramPoint // Symbol appears at different program points (exploded
                    // nodes)
};

// Symbolic value binding information
struct SymbolicBindingInfo {
  std::string SymbolName;
  std::set<std::string>
      TemporalContexts;              // Which temporal contexts use this symbol
  std::set<std::string> Subformulas; // Which subformulas use this symbol
  std::set<SourceLocation>
      ProgramPoints;             // Program points where symbol is referenced
  bool NeedsGDMStorage;          // Whether symbol needs GDM storage
  SymbolRef StoredSymbolicValue; // The actual symbolic value stored in GDM

  SymbolicBindingInfo()
      : SymbolName(""), NeedsGDMStorage(false), StoredSymbolicValue(nullptr) {}

  SymbolicBindingInfo(const std::string &name)
      : SymbolName(name), NeedsGDMStorage(false), StoredSymbolicValue(nullptr) {
  }
};

// General symbolic value persistence manager
class SymbolicValuePersistenceManager {
private:
  std::map<std::string, SymbolicBindingInfo> SymbolInfo;
  std::set<std::string> SymbolsNeedingGDM;

public:
  // Analyze LTL formula for symbolic value persistence requirements
  void
  analyzeFormulaForPersistence(const std::shared_ptr<LTLFormulaNode> &formula) {
    SymbolInfo.clear();
    SymbolsNeedingGDM.clear();

    // Recursively analyze the formula tree
    analyzeNodeForPersistence(formula, "root", SourceLocation());

    // Determine which symbols need GDM storage
    determineGDMRequirements();

    // Setup cross-context symbol sharing
    setupCrossContextSharing();
  }

  // Get all symbols that need GDM storage
  const std::set<std::string> &getSymbolsNeedingGDM() const {
    return SymbolsNeedingGDM;
  }

  // Get binding info for a specific symbol
  const SymbolicBindingInfo *
  getSymbolInfo(const std::string &symbolName) const {
    auto it = SymbolInfo.find(symbolName);
    return it != SymbolInfo.end() ? &it->second : nullptr;
  }

  // Check if a symbol needs GDM storage
  bool needsGDMStorage(const std::string &symbolName) const {
    return SymbolsNeedingGDM.find(symbolName) != SymbolsNeedingGDM.end();
  }

  // Get all temporal contexts that use a symbol
  std::set<std::string>
  getTemporalContextsForSymbol(const std::string &symbolName) const {
    const auto *info = getSymbolInfo(symbolName);
    return info ? info->TemporalContexts : std::set<std::string>();
  }

  // Get all subformulas that use a symbol
  std::set<std::string>
  getSubformulasForSymbol(const std::string &symbolName) const {
    const auto *info = getSymbolInfo(symbolName);
    return info ? info->Subformulas : std::set<std::string>();
  }

  // Generate persistence analysis report
  std::string generatePersistenceReport() const {
    std::string report = "Symbolic Value Persistence Analysis:\n";
    report += "Symbols requiring GDM storage: " +
              std::to_string(SymbolsNeedingGDM.size()) + "\n\n";

    for (const auto &symbol : SymbolsNeedingGDM) {
      const auto *info = getSymbolInfo(symbol);
      if (info) {
        report += "Symbol: " + symbol + "\n";
        report += "  Temporal Contexts: " +
                  std::to_string(info->TemporalContexts.size()) + "\n";
        report +=
            "  Subformulas: " + std::to_string(info->Subformulas.size()) + "\n";
        report +=
            "  Program Points: " + std::to_string(info->ProgramPoints.size()) +
            "\n";
        report +=
            "  GDM Storage: " +
            std::string(info->NeedsGDMStorage ? "Required" : "Not Required") +
            "\n\n";
      }
    }

    return report;
  }

private:
  // Recursively analyze LTL formula nodes for persistence requirements
  void analyzeNodeForPersistence(const std::shared_ptr<LTLFormulaNode> &node,
                                 const std::string &context,
                                 SourceLocation location) {
    if (!node)
      return;

    // Analyze based on node type
    switch (node->Type) {
    case LTLNodeType::Atomic:
      analyzeAtomicNodeForPersistence(node, context, location);
      break;
    case LTLNodeType::And:
    case LTLNodeType::Or:
    case LTLNodeType::Implies:
      analyzeBinaryOpNodeForPersistence(node, context, location);
      break;
    case LTLNodeType::Not:
    case LTLNodeType::Globally:
    case LTLNodeType::Eventually:
    case LTLNodeType::Next:
      analyzeUnaryOpNodeForPersistence(node, context, location);
      break;
    case LTLNodeType::Until:
    case LTLNodeType::Release:
      analyzeBinaryOpNodeForPersistence(node, context, location);
      break;
    }
  }

  // Analyze atomic propositions for persistence requirements
  void
  analyzeAtomicNodeForPersistence(const std::shared_ptr<LTLFormulaNode> &node,
                                  const std::string &context,
                                  SourceLocation location) {
    if (node->Binding.SymbolName.empty()) {
      return; // No symbol binding
    }

    std::string symbolName = node->Binding.SymbolName;

    // Get or create symbol info
    auto &info = SymbolInfo[symbolName];
    info.SymbolName = symbolName;

    // Record temporal context
    info.TemporalContexts.insert(context);

    // Record subformula (using function name as subformula identifier)
    if (!node->FunctionName.empty()) {
      info.Subformulas.insert(node->FunctionName);
    }

    // Record program point (if available)
    if (location.isValid()) {
      info.ProgramPoints.insert(location);
    }
  }

  // Analyze binary operators for persistence requirements
  void
  analyzeBinaryOpNodeForPersistence(const std::shared_ptr<LTLFormulaNode> &node,
                                    const std::string &context,
                                    SourceLocation location) {
    for (const auto &child : node->Children) {
      analyzeNodeForPersistence(child, context, location);
    }
  }

  // Analyze unary operators for persistence requirements
  void
  analyzeUnaryOpNodeForPersistence(const std::shared_ptr<LTLFormulaNode> &node,
                                   const std::string &context,
                                   SourceLocation location) {
    // Create new temporal context for temporal operators
    std::string newContext = context;
    switch (node->Type) {
    case LTLNodeType::Globally:
      newContext += ".G";
      break;
    case LTLNodeType::Eventually:
      newContext += ".F";
      break;
    case LTLNodeType::Next:
      newContext += ".X";
      break;
    default:
      break;
    }

    // Analyze children in the new context
    for (const auto &child : node->Children) {
      analyzeNodeForPersistence(child, newContext, location);
    }
  }

  // Determine which symbols need GDM storage based on usage patterns
  void determineGDMRequirements() {
    for (auto &pair : SymbolInfo) {
      auto &info = pair.second;

      // Check usage patterns to determine if GDM storage is needed
      bool needsGDM = false;

      // Pattern 1: Multiple temporal contexts
      if (info.TemporalContexts.size() > 1) {
        needsGDM = true;
      }

      // Pattern 2: Multiple subformulas (even in same context)
      if (info.Subformulas.size() > 1) {
        needsGDM = true;
      }

      // Pattern 3: Multiple program points
      if (info.ProgramPoints.size() > 1) {
        needsGDM = true;
      }

      // Pattern 4: Multiple occurrences in general
      if (info.TemporalContexts.size() + info.Subformulas.size() > 2) {
        needsGDM = true;
      }

      info.NeedsGDMStorage = needsGDM;
      if (needsGDM) {
        SymbolsNeedingGDM.insert(info.SymbolName);
      }
    }
  }

  // Setup cross-context symbol sharing mechanisms
  void setupCrossContextSharing() {
    // This will be called by the framework to set up the cross-context sharing
    // The actual sharing logic is implemented in the event handlers
  }
};

// LTL State for Büchi automaton
class LTLState {
public:
  std::string StateID;
  std::set<std::string> AtomicPropositions;
  std::vector<std::string> PendingFormulas;
  bool IsAccepting;
  std::string DiagnosticLabel;

  LTLState(const std::string &id, bool accepting = false)
      : StateID(id), IsAccepting(accepting) {}

  void addAtomicProposition(const std::string &prop) {
    AtomicPropositions.insert(prop);
  }

  void addPendingFormula(const std::string &formula) {
    PendingFormulas.push_back(formula);
  }
};

// Büchi automaton for LTL monitoring
class LTLAutomaton {
private:
  std::vector<std::shared_ptr<LTLState>> States;
  std::map<std::pair<std::string, std::set<std::string>>,
           std::shared_ptr<LTLState>>
      Transitions;
  std::map<std::string, std::string> DiagnosticLabels;
  std::shared_ptr<LTLState> InitialState;

public:
  LTLAutomaton() = default;

  void addState(std::shared_ptr<LTLState> state) {
    States.push_back(state);
    if (!InitialState) {
      InitialState = state;
    }
  }

  void addTransition(std::shared_ptr<LTLState> from,
                     const std::set<std::string> &props,
                     std::shared_ptr<LTLState> to) {
    Transitions[{from->StateID, props}] = to;
  }

  void setDiagnosticLabel(const std::string &stateID,
                          const std::string &label) {
    DiagnosticLabels[stateID] = label;
  }

  std::shared_ptr<LTLState>
  processEvent(std::shared_ptr<LTLState> currentState,
               const std::set<std::string> &propositions) {
    auto key = std::make_pair(currentState->StateID, propositions);
    auto it = Transitions.find(key);
    return it != Transitions.end() ? it->second : currentState;
  }

  bool isAccepting(std::shared_ptr<LTLState> state) const {
    return state && state->IsAccepting;
  }

  std::string getDiagnosticLabel(std::shared_ptr<LTLState> state) const {
    if (!state)
      return "";
    auto it = DiagnosticLabels.find(state->StateID);
    return it != DiagnosticLabels.end() ? it->second : "";
  }

  std::shared_ptr<LTLState> getInitialState() const { return InitialState; }

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
    if (!formula || !currentState || !automaton)
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
    case LTLNodeType::Implies:
      buildImpliesState(formula, currentState, automaton);
      break;
    case LTLNodeType::Not:
      buildNotState(formula, currentState, automaton);
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
      break;
    }
  }

  // Build state for atomic proposition
  void buildAtomicState(std::shared_ptr<LTLFormulaNode> formula,
                        std::shared_ptr<LTLState> currentState,
                        LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton)
      return;

    // Add atomic proposition to current state
    std::string prop = formula->toString();
    currentState->AtomicPropositions.insert(prop);

    // Add diagnostic label if present
    if (!formula->DiagnosticLabel.empty()) {
      currentState->DiagnosticLabel = formula->DiagnosticLabel;
    }

    // Add state to automaton
    automaton->addState(currentState);
  }

  // Build state for binary operators
  void buildAndState(std::shared_ptr<LTLFormulaNode> formula,
                     std::shared_ptr<LTLState> currentState,
                     LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton || formula->Children.size() < 2)
      return;

    // Process both children
    buildAutomatonStates(formula->Children[0], currentState, automaton);
    buildAutomatonStates(formula->Children[1], currentState, automaton);
  }

  void buildOrState(std::shared_ptr<LTLFormulaNode> formula,
                    std::shared_ptr<LTLState> currentState,
                    LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton || formula->Children.size() < 2)
      return;

    // Create separate states for each child
    auto leftState = createState("or_left", false);
    auto rightState = createState("or_right", false);

    buildAutomatonStates(formula->Children[0], leftState, automaton);
    buildAutomatonStates(formula->Children[1], rightState, automaton);

    // Add transitions from current state to both children
    automaton->addTransition(currentState, std::set<std::string>(), leftState);
    automaton->addTransition(currentState, std::set<std::string>(), rightState);
  }

  void buildImpliesState(std::shared_ptr<LTLFormulaNode> formula,
                         std::shared_ptr<LTLState> currentState,
                         LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton || formula->Children.size() < 2)
      return;

    // A → B is equivalent to ¬A ∨ B
    auto notA =
        std::make_shared<UnaryOpNode>(LTLNodeType::Not, formula->Children[0]);
    auto orNode = std::make_shared<BinaryOpNode>(LTLNodeType::Or, notA,
                                                 formula->Children[1]);

    buildOrState(orNode, currentState, automaton);
  }

  // Build state for unary operators
  void buildNotState(std::shared_ptr<LTLFormulaNode> formula,
                     std::shared_ptr<LTLState> currentState,
                     LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton || formula->Children.empty())
      return;

    // For now, just process the child
    buildAutomatonStates(formula->Children[0], currentState, automaton);
  }

  void buildGloballyState(std::shared_ptr<LTLFormulaNode> formula,
                          std::shared_ptr<LTLState> currentState,
                          LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton || formula->Children.empty())
      return;

    // G φ means φ must be true in all future states
    // Create a loop state that always requires φ
    auto loopState = createState("globally", true);
    buildAutomatonStates(formula->Children[0], loopState, automaton);

    // Add transition from current state to loop state
    automaton->addTransition(currentState, std::set<std::string>(), loopState);
    // Add self-loop to maintain the globally property
    automaton->addTransition(loopState, std::set<std::string>(), loopState);
  }

  void buildEventuallyState(std::shared_ptr<LTLFormulaNode> formula,
                            std::shared_ptr<LTLState> currentState,
                            LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton || formula->Children.empty())
      return;

    // F φ means φ must eventually be true
    // Create a state that can accept φ at any time
    auto eventuallyState = createState("eventually", false);
    buildAutomatonStates(formula->Children[0], eventuallyState, automaton);

    // Add transition from current state to eventually state
    automaton->addTransition(currentState, std::set<std::string>(),
                             eventuallyState);
    // Add self-loop to allow waiting for φ
    automaton->addTransition(currentState, std::set<std::string>(),
                             currentState);
  }

  void buildNextState(std::shared_ptr<LTLFormulaNode> formula,
                      std::shared_ptr<LTLState> currentState,
                      LTLAutomaton *automaton) {
    if (!formula || !currentState || !automaton || formula->Children.empty())
      return;

    // X φ means φ must be true in the next state
    auto nextState = createState("next", false);
    buildAutomatonStates(formula->Children[0], nextState, automaton);

    // Add transition from current state to next state
    automaton->addTransition(currentState, std::set<std::string>(), nextState);
  }
};

// Forward declaration
class LTLFormulaBuilder;

// Binding-driven event creation system
class BindingDrivenEventCreator {
private:
  std::map<std::string, std::map<std::string, BindingType>> FunctionBindings;

public:
  // Register function binding information from DSL formula
  void registerFunctionBinding(const std::string &functionName,
                               const std::string &symbolName,
                               BindingType bindingType) {
    FunctionBindings[functionName][symbolName] = bindingType;
  }

  // Get binding type for a function and symbol
  BindingType getBindingType(const std::string &functionName,
                             const std::string &symbolName) const {
    auto funcIt = FunctionBindings.find(functionName);
    if (funcIt != FunctionBindings.end()) {
      auto symbolIt = funcIt->second.find(symbolName);
      if (symbolIt != funcIt->second.end()) {
        return symbolIt->second;
      }
    }
    return BindingType::Variable; // Default fallback
  }

  // Extract symbol from call event based on binding type
  SymbolRef extractSymbolFromCall(const CallEvent &Call,
                                  const std::string &functionName,
                                  const std::string &symbolName) const {
    BindingType bindingType = getBindingType(functionName, symbolName);

    switch (bindingType) {
    case BindingType::ReturnValue:
      return Call.getReturnValue().getAsSymbol();

    case BindingType::FirstParameter:
      return Call.getNumArgs() > 0 ? Call.getArgSVal(0).getAsSymbol() : nullptr;

    case BindingType::NthParameter:
      // For now, assume first parameter - could be enhanced to track parameter
      // index
      return Call.getNumArgs() > 0 ? Call.getArgSVal(0).getAsSymbol() : nullptr;

    case BindingType::Variable:
    default:
      return nullptr;
    }
  }

  // Check if we have binding information for a function
  bool hasBindingInfo(const std::string &functionName) const {
    return FunctionBindings.find(functionName) != FunctionBindings.end();
  }
};

// Enhanced LTL Formula Builder with general symbolic value persistence
class LTLFormulaBuilder {
private:
  std::shared_ptr<LTLFormulaNode> RootFormula;
  SymbolicValuePersistenceManager PersistenceManager;
  std::vector<std::string> DiagnosticLabels;
  std::vector<SymbolBinding> SymbolBindings;
  std::set<std::string> FunctionNames;
  // Map node IDs to nodes for external mappings (e.g., SPOT APs)
  std::map<int, LTLFormulaNode *> IdToNode;

public:
  LTLFormulaBuilder() = default;

  void setFormula(std::shared_ptr<LTLFormulaNode> formula) {
    RootFormula = formula;

    // Analyze formula for symbolic value persistence requirements
    PersistenceManager.analyzeFormulaForPersistence(formula);

    // Extract diagnostic labels
    extractDiagnosticLabels(formula);

    // Extract symbol bindings
    extractSymbolBindings(formula);

    // Extract function names
    extractFunctionNames(formula);

    // Index nodes by NodeID and set parent pointers recursively (safety)
    indexNodes(formula.get());
  }

  std::string getFormulaString() const {
    return RootFormula ? RootFormula->toString() : "";
  }

  std::string getStructuralInfo() const {
    if (!RootFormula)
      return "";

    std::string info = "Formula Structure:\n";
    info += "  Root: " + RootFormula->getStructuralInfo() + "\n";
    info += "  Symbols requiring GDM: " +
            std::to_string(PersistenceManager.getSymbolsNeedingGDM().size()) +
            "\n";

    for (const auto &symbol : PersistenceManager.getSymbolsNeedingGDM()) {
      const auto *info_ptr = PersistenceManager.getSymbolInfo(symbol);
      if (info_ptr) {
        info += "    - " + symbol + " (";
        info +=
            "contexts: " + std::to_string(info_ptr->TemporalContexts.size()) +
            ", ";
        info += "subformulas: " + std::to_string(info_ptr->Subformulas.size()) +
                ", ";
        info +=
            "program points: " + std::to_string(info_ptr->ProgramPoints.size());
        info += ")\n";
      }
    }

    return info;
  }

  std::vector<std::string> getDiagnosticLabels() const {
    return DiagnosticLabels;
  }

  std::vector<SymbolBinding> getSymbolBindings() const {
    return SymbolBindings;
  }

  std::set<std::string> getFunctionNames() const { return FunctionNames; }

  // New methods for general symbolic value persistence
  const SymbolicValuePersistenceManager &getPersistenceManager() const {
    return PersistenceManager;
  }

  std::set<std::string> getSymbolsNeedingGDM() const {
    return PersistenceManager.getSymbolsNeedingGDM();
  }

  bool needsGDMStorage(const std::string &symbolName) const {
    return PersistenceManager.needsGDMStorage(symbolName);
  }

  std::string getPersistenceReport() const {
    return PersistenceManager.generatePersistenceReport();
  }

  // Expose the root for external traversals (e.g., SPOT conversion)
  const LTLFormulaNode *getRootNode() const { return RootFormula.get(); }

  // Lookup node by ID
  LTLFormulaNode *getNodeByID(int id) const {
    auto it = IdToNode.find(id);
    return it == IdToNode.end() ? nullptr : it->second;
  }

  // Find nearest ancestor (including self) carrying a diagnostic label
  const LTLFormulaNode *findNearestDiagnosticAncestor(const LTLFormulaNode *node) const {
    const LTLFormulaNode *cur = node;
    while (cur) {
      if (!cur->DiagnosticLabel.empty())
        return cur;
      cur = cur->Parent;
    }
    return nullptr;
  }

  std::unique_ptr<LTLAutomaton> generateAutomaton() const {
    if (!RootFormula) {
      return nullptr;
    }

    LTLParser parser(RootFormula);
    return parser.generateAutomaton();
  }

  // Extract binding information for event creation
  void
  populateBindingDrivenEventCreator(BindingDrivenEventCreator &creator) const {
    if (!RootFormula) {
      return;
    }

    extractFunctionBindings(RootFormula, creator);
  }

private:
  void extractDiagnosticLabels(const std::shared_ptr<LTLFormulaNode> &node) {
    if (!node)
      return;

    if (!node->DiagnosticLabel.empty()) {
      DiagnosticLabels.push_back(node->DiagnosticLabel);
    }

    for (const auto &child : node->Children) {
      extractDiagnosticLabels(child);
    }
  }

  void extractSymbolBindings(const std::shared_ptr<LTLFormulaNode> &node) {
    if (!node)
      return;

    if (!node->Binding.SymbolName.empty()) {
      SymbolBindings.push_back(node->Binding);
    }

    for (const auto &child : node->Children) {
      extractSymbolBindings(child);
    }
  }

  void extractFunctionNames(const std::shared_ptr<LTLFormulaNode> &node) {
    if (!node)
      return;

    if (!node->FunctionName.empty()) {
      FunctionNames.insert(node->FunctionName);
    }

    for (const auto &child : node->Children) {
      extractFunctionNames(child);
    }
  }

  void extractFunctionBindings(const std::shared_ptr<LTLFormulaNode> &node,
                               BindingDrivenEventCreator &creator) const {
    if (!node)
      return;

    // If this is an atomic node with a function name and binding, register it
    if (!node->FunctionName.empty() && !node->Binding.SymbolName.empty()) {
      creator.registerFunctionBinding(
          node->FunctionName, node->Binding.SymbolName, node->Binding.Type);
    }

    // Recursively process children
    for (const auto &child : node->Children) {
      extractFunctionBindings(child, creator);
    }
  }

  void indexNodes(LTLFormulaNode *node) {
    if (!node)
      return;
    IdToNode[node->NodeID] = node;
    for (const auto &child : node->Children) {
      if (child && child->Parent == nullptr)
        child->Parent = node;
      indexNodes(child.get());
    }
  }
};

// Generic event types for the framework
enum class EventType {
  PostCall,   // Function call completed
  PreCall,    // Function call about to start
  DeadSymbols, // Symbols are no longer reachable
  EndFunction, // Function is ending; finalize obligations for this frame
  PointerEscape // Symbol escapes current function/frame ownership
};

// Generic event structure
struct GenericEvent {
  EventType Type;
  std::string FunctionName;
  std::string SymbolName;
  SymbolRef Symbol;
  SourceLocation Location;

  GenericEvent(EventType t, const std::string &func, const std::string &sym,
               SymbolRef s, SourceLocation loc)
      : Type(t), FunctionName(func), SymbolName(sym), Symbol(s), Location(loc) {
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
  std::string PropertyName;
  LTLFormulaBuilder FormulaBuilder;
  const CheckerBase *Checker;
  BindingDrivenEventCreator EventCreator;
  // SPOT-backed monitor is owned in the checker TU to avoid header cycles

public:
  MonitorAutomaton(std::unique_ptr<PropertyDefinition> prop,
                   const CheckerBase *C)
      : PropertyName(prop->getPropertyName()),
        FormulaBuilder(prop->getFormulaBuilder()), Checker(C) {
    // Populate binding-driven event creator with formula information
    FormulaBuilder.populateBindingDrivenEventCreator(EventCreator);
    // Temporal monitoring is handled by the SPOT-based monitor in the checker TU.
  }

  void handleEvent(const GenericEvent &event, CheckerContext &C) {
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL] handleEvent: type=";
      switch (event.Type) {
      case EventType::PostCall: llvm::errs() << "PostCall"; break;
      case EventType::PreCall: llvm::errs() << "PreCall"; break;
      case EventType::DeadSymbols: llvm::errs() << "DeadSymbols"; break;
      case EventType::EndFunction: llvm::errs() << "EndFunction"; break;
      case EventType::PointerEscape: llvm::errs() << "PointerEscape"; break;
      }
      llvm::errs() << ", fn=" << event.FunctionName
                   << ", sym=" << event.SymbolName << "\n";
    }
    // Generic, checker-agnostic lifecycle modeling driven by bindings.
    // This block purposefully contains no malloc/free specific strings.
    ProgramStateRef State = C.getState();

    switch (event.Type) {
    case EventType::PostCall: {
      if (event.Symbol && !event.FunctionName.empty() && !event.SymbolName.empty()) {
        // Treat a PostCall bound to a ReturnValue as a creation event
        BindingType BT = EventCreator.getBindingType(event.FunctionName, event.SymbolName);
        if (BT == BindingType::ReturnValue) {
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL] create: " << event.FunctionName << "(" << event.SymbolName << ") -> Active\n";
            }
            State = State->set<::SymbolStates>(event.Symbol, ::SymbolState::Active);
            State = State->add<::PendingLeakSet>(event.Symbol);
            // Add a binding note similar to checker format for traceability
            std::string internal = "sym_" + std::to_string(event.Symbol->getSymbolID());
            std::string var = event.SymbolName.empty() ? std::string("x") : event.SymbolName;
            std::string note = std::string("symbol \"") + var + "\" is bound here (internal symbol: " + internal + ")";
            const NoteTag *NT = C.getNoteTag([note]() { return note; });
            C.addTransition(State, NT);
        }
      }
      break;
    }
    case EventType::PreCall: {
      if (event.Symbol && !event.FunctionName.empty() && !event.SymbolName.empty()) {
        // Treat a PreCall bound to a parameter as a destruction event
        BindingType BT = EventCreator.getBindingType(event.FunctionName, event.SymbolName);
        if (BT == BindingType::FirstParameter || BT == BindingType::NthParameter) {
          const ::SymbolState *CurPtr = State->get<::SymbolStates>(event.Symbol);
          ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
          if (Cur == ::SymbolState::Active) {
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL] destroy: " << event.FunctionName << "(" << event.SymbolName << ") -> Inactive\n";
            }
            State = State->set<::SymbolStates>(event.Symbol, ::SymbolState::Inactive);
            State = State->remove<::GenericSymbolMap>(event.Symbol);
            State = State->remove<::PendingLeakSet>(event.Symbol);
            C.addTransition(State);
          } else if (Cur == ::SymbolState::Inactive) {
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL] double-destroy detected for sym " << event.SymbolName << "\n";
            }
            // Double destruction: emit violation
            ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
            if (ErrorNode) {
              static const BugType BT{Checker, "temporal_violation", "EmbeddedDSLMonitor"};
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
      break;
    }
    case EventType::DeadSymbols: {
      // Intentionally no-op here; leaks reported at EndFunction for better location
      break;
    }
    case EventType::PointerEscape: {
      if (event.Symbol) {
        // Transfer ownership out of this frame: do not report leak here
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL] escape: dropping PendingLeak obligation for "
                       << event.SymbolName << "\n";
        }
        State = State->remove<::PendingLeakSet>(event.Symbol);
        C.addTransition(State);
      }
      break;
    }
    case EventType::EndFunction: {
      // Emit leaks for any symbols still pending at function end.
      if (edslDebugEnabled()) {
        unsigned pendingCount = 0;
        for (auto _ : State->get<::PendingLeakSet>()) (void)_, ++pendingCount;
        llvm::errs() << "[EDSL] end-function: pending=" << pendingCount << "\n";
      }
      for (auto Sym : State->get<::PendingLeakSet>()) {
        // If the symbol is provably null on this path, drop obligation silently.
        ConditionTruthVal __IsNull = C.getConstraintManager().isNull(State, Sym);
        if (__IsNull.isConstrainedTrue()) {
          State = State->remove<::GenericSymbolMap>(Sym);
          State = State->remove<::SymbolStates>(Sym);
          State = State->remove<::PendingLeakSet>(Sym);
          continue;
        }
        ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
        if (ErrorNode) {
          static const BugType BT{Checker, "temporal_violation", "EmbeddedDSLMonitor"};
          std::string msg = "resource not destroyed (violates exactly-once)";
          std::string internal = "sym_" + std::to_string(Sym->getSymbolID());
          msg += " (internal symbol: " + internal + ")";
          auto R = std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
          R->markInteresting(Sym);
          // Hint for path location: end-of-function
          const NoteTag *EndTag = C.getNoteTag([]() { return std::string("function ends here"); });
          C.addTransition(C.getState(), EndTag);
          C.emitReport(std::move(R));
        }
        State = State->remove<::GenericSymbolMap>(Sym);
        State = State->remove<::SymbolStates>(Sym);
        State = State->remove<::PendingLeakSet>(Sym);
      }
      C.addTransition(State);
      break;
    }
    }
  }

  std::string getPropertyName() const { return PropertyName; }
  LTLFormulaBuilder getFormulaBuilder() const { return FormulaBuilder; }

  // Extract atomic propositions from an event
  std::set<std::string> extractPropositions(const GenericEvent &event, CheckerContext &C) const {
    std::set<std::string> propositions;
    ProgramStateRef State = C.getState();

    // Add function call proposition
    if (!event.FunctionName.empty()) {
      propositions.insert(event.FunctionName + "(" + event.SymbolName + ")");
    }

    // Add symbol proposition if available
    if (!event.SymbolName.empty() && event.SymbolName != "unknown") {
      propositions.insert(event.SymbolName);
    }

    return propositions;
  }

  // Create event using binding-driven approach
  dsl::GenericEvent createBindingDrivenEvent(const CallEvent &Call,
                                             EventType eventType,
                                             CheckerContext &C) const {
    std::string funcName = Call.getCalleeIdentifier()
                               ? Call.getCalleeIdentifier()->getName().str()
                               : "unknown";

    // If we have binding information for this function, use it
    if (EventCreator.hasBindingInfo(funcName)) {
      // For now, we'll use the first symbol we find for this function
      // In a more sophisticated implementation, we could match symbols more
      // precisely
      SymbolRef Sym = nullptr;
      std::string symbolName = "unknown";

      // Try to find a symbol using the binding information
      // This is a simplified approach - in practice, we'd need more
      // sophisticated matching
      for (const auto &binding : FormulaBuilder.getSymbolBindings()) {
        if (EventCreator.getBindingType(funcName, binding.SymbolName) !=
            BindingType::Variable) {
          Sym = EventCreator.extractSymbolFromCall(Call, funcName,
                                                   binding.SymbolName);
          if (Sym) {
            symbolName = binding.SymbolName;
            break;
          }
        }
      }

      // If binding-based extraction failed, fall back to default extraction
      if (!Sym) {
      if (eventType == EventType::PostCall) {
        Sym = Call.getReturnValue().getAsSymbol();
        symbolName = Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
      } else {
        // Prefer the underlying stored symbol of the region argument, if any
        Sym = nullptr;
        if (Call.getNumArgs() > 0) {
          SVal Arg = Call.getArgSVal(0);
          if (const MemRegion *MR = Arg.getAsRegion()) {
            SVal Stored = C.getState()->getSVal(MR);
            if (SymbolRef StoredSym = Stored.getAsSymbol()) {
              Sym = StoredSym;
            }
          }
          if (!Sym)
            Sym = Arg.getAsSymbol();
        }
        symbolName = Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
      }
      }

      return dsl::GenericEvent(eventType, funcName, symbolName, Sym,
                               Call.getSourceRange().getBegin());
    } else {
      // Fallback to traditional approach
      SymbolRef Sym = nullptr;
      std::string symbolName = "unknown";

      if (eventType == EventType::PostCall) {
        Sym = Call.getReturnValue().getAsSymbol();
        symbolName =
            Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
      } else {
        Sym = Call.getNumArgs() > 0 ? Call.getArgSVal(0).getAsSymbol() : nullptr;
        symbolName =
            Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
      }

      return dsl::GenericEvent(eventType, funcName, symbolName, Sym,
                               Call.getSourceRange().getBegin());
    }
  }

private:
  // (Legacy propositional extraction removed; SPOT handles temporal logic.)

  // Emit diagnostic for automaton-based violations
  void emitDiagnostic(const std::string &diagnostic, const GenericEvent &event,
                      CheckerContext &C) {
    if (!event.Symbol) {
      return;
    }

    // Generate error node
    ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
    if (!ErrorNode) {
      return;
    }

    // Create generic bug type for any temporal property violation
    static const BugType GenericBT{Checker, "temporal_violation",
                                   "EmbeddedDSLMonitor"};
    const BugType *BT = &GenericBT;

    // Enhance diagnostic message with internal symbol name for correlation
    std::string enhancedDiagnostic = diagnostic;
    
    // Add internal symbol name for correlation with notes
    if (event.Symbol) {
      std::string internalSymbolName = "sym_" + std::to_string(event.Symbol->getSymbolID());
      enhancedDiagnostic += " (internal symbol: " + internalSymbolName + ")";
    }

    auto R =
        std::make_unique<PathSensitiveBugReport>(*BT, enhancedDiagnostic, ErrorNode);
    R->markInteresting(event.Symbol);
    C.emitReport(std::move(R));
  }

  // Add a note about symbol binding
  void addSymbolBindingNote(const GenericEvent &event, CheckerContext &C) {
    if (!event.Symbol || !event.Location.isValid()) {
      return;
    }

    // Determine the formula variable name
    std::string formulaVar = "x"; // Default formula variable name
    
    // Try to find the actual formula variable name from the binding
    for (const auto &binding : FormulaBuilder.getSymbolBindings()) {
      if (binding.SymbolName == event.SymbolName) {
        formulaVar = binding.SymbolName;
        break;
      }
    }

    // Create the note message
    std::string internalSymbolName = "sym_" + std::to_string(event.Symbol->getSymbolID());
    std::string noteMessage = "symbol \"" + formulaVar + "\" is bound here (internal symbol: " + 
                             internalSymbolName + ")";

    // Create a note using getNoteTag
    const NoteTag *noteTag = C.getNoteTag([noteMessage]() { return noteMessage; });
    C.addTransition(C.getState(), noteTag);
  }
};

// Generic ASTMatchers wrapper
class PatternMatcher {
public:
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
    C.addTransition(State->set<::GenericSymbolMap>(sym, value));
  }

  static std::string getSymbolValue(ProgramStateRef State, SymbolRef sym) {
    if (const std::string *value = State->get<::GenericSymbolMap>(sym)) {
      return *value;
    }
    return "";
  }

  static void removeSymbol(ProgramStateRef State, SymbolRef sym,
                           CheckerContext &C) {
    C.addTransition(State->remove<::GenericSymbolMap>(sym));
  }

  static bool hasSymbol(ProgramStateRef State, SymbolRef sym) {
    return State->get<::GenericSymbolMap>(sym) != nullptr;
  }
};

// Generic Event Handler for any temporal property
class GenericEventHandler : public EventHandler {
private:
  const CheckerBase *Checker;

public:
  GenericEventHandler(const CheckerBase *C) : Checker(C) {}

  std::string getDescription() const override {
    return "Generic temporal property monitor";
  }

  void handleEvent(const GenericEvent &event, CheckerContext &C) override {
    // Generic event handling - all logic is now in the automaton
    // This handler can be extended for custom event processing if needed
    (void)event;
    (void)C;
  }
};

// Generic Property Implementation
class GenericProperty : public PropertyDefinition {
private:
  LTLFormulaBuilder FormulaBuilder;
  std::string PropertyName;
  std::string FormulaString;

public:
  GenericProperty(const std::string &name, const std::string &formulaStr,
                  std::shared_ptr<LTLFormulaNode> formula)
      : PropertyName(name), FormulaString(formulaStr) {
    FormulaBuilder.setFormula(formula);
  }

  std::string getTemporalLogicFormula() const override { return FormulaString; }

  std::string getPropertyName() const override { return PropertyName; }

  LTLFormulaBuilder getFormulaBuilder() const override {
    return FormulaBuilder;
  }

  std::unique_ptr<EventHandler>
  createEventHandler(const CheckerBase *Checker) override {
    return std::make_unique<GenericEventHandler>(Checker);
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

    auto lockCall =
        DSL::Call("lock", SymbolBinding(BindingType::FirstParameter, "x"));
    auto unlockCall =
        DSL::Call("unlock", SymbolBinding(BindingType::FirstParameter, "x"));

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
    return std::make_unique<GenericEventHandler>(Checker);
  }
};

} // namespace dsl
} // namespace ento
} // namespace clang

#endif // LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H