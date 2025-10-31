// Embedded DSL Framework for Temporal Logic-Based Static Analysis
// This framework provides a domain-specific language for defining temporal
// logic properties and automatically generating monitor automatons for
// violation detection.

#ifndef LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H
#define LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H

#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclBase.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

// Generic symbol state for any temporal property
enum class SymbolState {
  Uninitialized, // Symbol not yet processed
  Active,        // Symbol is in active state
  Inactive,      // Symbol is in inactive state
  Violated,      // Symbol violates the property
  Invalid        // Invalid state
};

// (Removed unused SymbolContext enum)

// State trait registrations
// NOTE: All GDM traits are defined in EmbeddedDSLMonitorChecker.cpp to avoid
// multiple definition issues across translation units. Use the API functions
// below to access them from other translation units.

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

// API functions to access GDM traits from other translation units
// These functions are implemented in EmbeddedDSLMonitorChecker.cpp

// TrackedSymbols API
ProgramStateRef addTrackedSymbol(ProgramStateRef State, SymbolRef Sym);
ProgramStateRef removeTrackedSymbol(ProgramStateRef State, SymbolRef Sym);
bool containsTrackedSymbol(ProgramStateRef State, SymbolRef Sym);
size_t getTrackedSymbolCount(ProgramStateRef State);
std::vector<SymbolRef> getTrackedSymbols(ProgramStateRef State);

// GenericSymbolMap API
ProgramStateRef setGenericSymbolMap(ProgramStateRef State, SymbolRef Sym,
                                    const std::string &Value);
ProgramStateRef removeGenericSymbolMap(ProgramStateRef State, SymbolRef Sym);
const std::string *getGenericSymbolMap(ProgramStateRef State, SymbolRef Sym);
bool hasGenericSymbolMap(ProgramStateRef State, SymbolRef Sym);

// SymbolStates API
ProgramStateRef setSymbolState(ProgramStateRef State, SymbolRef Sym,
                               SymbolState SymbolState);
const SymbolState *getSymbolState(ProgramStateRef State, SymbolRef Sym);
bool isSymbolActive(ProgramStateRef State, SymbolRef Sym);
bool isSymbolInactive(ProgramStateRef State, SymbolRef Sym);

// SymbolToRegionMap API
ProgramStateRef setSymbolToRegionMap(ProgramStateRef State, SymbolRef Sym,
                                     const MemRegion *Region);
const MemRegion *getSymbolToRegionMap(ProgramStateRef State, SymbolRef Sym);

// AutomatonState API declarations
ProgramStateRef setAutomatonState(ProgramStateRef State, SymbolRef Sym,
                                  int StateValue);
const int *getAutomatonState(ProgramStateRef State, SymbolRef Sym);
ProgramStateRef removeAutomatonState(ProgramStateRef State, SymbolRef Sym);

// Symbol-Formula Variable Mapping API declarations
// NOTE: Multiple APs can match the same event, creating multiple SymbolRef ->
// FormulaVar mappings. Reverse lookup (FormulaVar -> SymbolRef) is ambiguous in
// this case and is not supported. Use SymbolRef -> FormulaVar mapping for
// forward lookups.
ProgramStateRef setSymbolFormulaMapping(ProgramStateRef State, SymbolRef Sym,
                                        const std::string &VarName);
const std::string *getSymbolFormulaVar(ProgramStateRef State, SymbolRef Sym);
ProgramStateRef removeSymbolFormulaMapping(ProgramStateRef State,
                                           SymbolRef Sym);

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
  ReturnValue,           // Function return value
  FirstParameter,        // First function parameter
  NthParameter,          // Nth function parameter
  ReturnValueNonNull,    // Function return value with non-null constraint
  FirstParameterNonNull, // First function parameter with non-null constraint
  NthParameterNonNull    // Nth function parameter with non-null constraint
};

// Helper functions for BindingType
inline bool isNonNullBinding(BindingType type) {
  return type == BindingType::ReturnValueNonNull ||
         type == BindingType::FirstParameterNonNull ||
         type == BindingType::NthParameterNonNull;
}

inline BindingType getBaseBindingType(BindingType type) {
  switch (type) {
  case BindingType::ReturnValueNonNull:
    return BindingType::ReturnValue;
  case BindingType::FirstParameterNonNull:
    return BindingType::FirstParameter;
  case BindingType::NthParameterNonNull:
    return BindingType::NthParameter;
  default:
    return type;
  }
}

// Symbol binding information
struct SymbolBinding {
  BindingType Type;
  std::string SymbolName;
  int ParameterIndex; // For NthParameter
  // Optional AST matcher used to filter/select call expressions for this
  // binding. If present, the binding applies only when the matcher matches the
  // call's origin expression.
  std::shared_ptr<clang::ast_matchers::internal::DynTypedMatcher> CallMatcher;
  bool HasMatcher;

  SymbolBinding(BindingType t, const std::string &name, int index = 0)
      : Type(t), SymbolName(name), ParameterIndex(index), CallMatcher(nullptr),
        HasMatcher(false) {}

  SymbolBinding(BindingType t, const std::string &name,
                const clang::ast_matchers::internal::DynTypedMatcher &M,
                int index = 0)
      : Type(t), SymbolName(name), ParameterIndex(index),
        CallMatcher(
            std::make_shared<clang::ast_matchers::internal::DynTypedMatcher>(
                M)),
        HasMatcher(true) {}

  bool matchesOriginExpr(const clang::Stmt *Origin,
                         clang::ASTContext &Ctx) const {
    (void)Ctx;
    // Placeholder: accept when origin exists; full DynTypedMatcher evaluation
    // can be enabled in a follow-up once ASTTypeTraits infra is stabilized.
    if (!HasMatcher)
      return true;
    return Origin != nullptr;
  }
};

// (Removed unused SymbolTrackingInfo struct)

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
  // Optional: call-shape matcher presence (matcher object optional for now)
  bool HasCallMatcher;
  // Virtual hook to evaluate an optional matcher carried by atomic nodes
  virtual bool matchOrigin(const Stmt *Origin, ASTContext &Ctx) const {
    (void)Origin;
    (void)Ctx;
    return true; // default: no matcher
  }

  // Virtual hook to get the matcher for AP registration
  virtual std::shared_ptr<clang::ast_matchers::internal::DynTypedMatcher>
  getMatcher() const {
    return nullptr; // default: no matcher
  }

  LTLFormulaNode(LTLNodeType t, const std::string &label = "")
      : Type(t), DiagnosticLabel(label), Children(),
        Binding(BindingType::ReturnValue, ""), FunctionName(), Value(),
        NodeID(nextNodeID()), Parent(nullptr), HasCallMatcher(false) {}

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
  std::shared_ptr<clang::ast_matchers::StatementMatcher> StoredStmtMatcher;
  bool HasStmtMatcher = false;

  AtomicNode(const std::string &funcName, const SymbolBinding &binding,
             const std::string &value = "")
      : LTLFormulaNode(LTLNodeType::Atomic) {
    FunctionName = funcName;
    Binding = binding;
    Value = value;
  }

  AtomicNode(const clang::ast_matchers::StatementMatcher &SM,
             const std::string &funcName, const SymbolBinding &binding)
      : LTLFormulaNode(LTLNodeType::Atomic) {
    FunctionName = funcName;
    Binding = binding;
    HasCallMatcher = true;
    HasStmtMatcher = true;
    StoredStmtMatcher =
        std::make_shared<clang::ast_matchers::StatementMatcher>(SM);
  }

  bool matchOrigin(const Stmt *Origin, ASTContext &Ctx) const override {
    if (!HasCallMatcher)
      return true;
    if (!Origin)
      return false;
    // Prefer the proper MatchFinder-driven API when we have a StatementMatcher
    if (HasStmtMatcher && StoredStmtMatcher) {
      auto Results =
          clang::ast_matchers::match(*StoredStmtMatcher, *Origin, Ctx);
      return !Results.empty();
    }
    return true;
  }

  std::shared_ptr<clang::ast_matchers::internal::DynTypedMatcher>
  getMatcher() const override {
    if (HasCallMatcher && HasStmtMatcher && StoredStmtMatcher) {
      return std::make_shared<clang::ast_matchers::internal::DynTypedMatcher>(
          clang::ast_matchers::internal::DynTypedMatcher(*StoredStmtMatcher));
    }
    return nullptr;
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

// Overload: accept a matcher; ignore function name entirely in this case.
// Removed DynTypedMatcher overloads in favor of StatementMatcher to comply with
// the LibASTMatchers MatchFinder calling conventions.

inline std::shared_ptr<LTLFormulaNode>
Call(const clang::ast_matchers::StatementMatcher &stmtMatcher,
     const SymbolBinding &binding) {
  return std::make_shared<AtomicNode>(stmtMatcher, "", binding);
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

// Predicate atom: symbol is provably non-null along the current path
inline std::shared_ptr<LTLFormulaNode>
IsNonNull(const std::string &symbolName) {
  auto node = std::make_shared<AtomicNode>(
      "__isnonnull", SymbolBinding(BindingType::ReturnValue, symbolName));
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

// (Removed legacy LTLState/LTLAutomaton/LTLParser scaffolding)

// Forward declaration
class LTLFormulaBuilder;

// AP-driven event creation system
class APDrivenEventCreator {
private:
  // AP Node ID -> SymbolName -> BindingType
  std::map<int, std::map<std::string, BindingType>> APBindings;

  // AP Node ID -> ASTMatcher for event matching
  std::map<int, std::shared_ptr<clang::ast_matchers::internal::DynTypedMatcher>>
      APMatchers;

public:
  // Register AP binding information from DSL formula
  void registerAPBinding(int apNodeId, const std::string &symbolName,
                         BindingType bindingType) {
    APBindings[apNodeId][symbolName] = bindingType;
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][INIT] Registered AP " << apNodeId
                   << " binding: symbol='" << symbolName
                   << "' type=" << (int)bindingType << "\n";
    }
  }

  // Register AP matcher for event matching
  void registerAPMatcher(
      int apNodeId,
      std::shared_ptr<clang::ast_matchers::internal::DynTypedMatcher> matcher) {
    APMatchers[apNodeId] = matcher;
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][INIT] Registered AP " << apNodeId
                   << " matcher for event matching\n";
    }
  }

  // Get binding type for an AP and symbol
  BindingType getBindingType(int apNodeId,
                             const std::string &symbolName) const {
    auto apIt = APBindings.find(apNodeId);
    if (apIt != APBindings.end()) {
      auto symbolIt = apIt->second.find(symbolName);
      if (symbolIt != apIt->second.end()) {
        return symbolIt->second;
      }
    }
    return BindingType::ReturnValue; // Default to ReturnValue if unknown
  }

  // Extract symbol from call event based on binding type
  SymbolRef extractSymbolFromCall(const CallEvent &Call, int apNodeId,
                                  const std::string &symbolName) const {
    BindingType bindingType = getBindingType(apNodeId, symbolName);
    BindingType baseType = getBaseBindingType(bindingType);

    switch (baseType) {
    case BindingType::ReturnValue:
      return Call.getReturnValue().getAsSymbol();

    case BindingType::FirstParameter:
      return Call.getNumArgs() > 0 ? Call.getArgSVal(0).getAsSymbol() : nullptr;

    case BindingType::NthParameter:
      // For now, assume first parameter - could be enhanced to track parameter
      // index
      return Call.getNumArgs() > 0 ? Call.getArgSVal(0).getAsSymbol() : nullptr;

    default:
      return nullptr;
    }
  }

  // Find all APs that match the given call event
  std::vector<int> findMatchingAPs(const CallEvent &Call,
                                   CheckerContext &C) const {
    std::vector<int> matchingAPs;
    const Stmt *Origin = Call.getOriginExpr();

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][AP_EVAL] Starting AP evaluation for call event\n";
      llvm::errs() << "[EDSL][AP_EVAL] Function: '"
                   << (Call.getCalleeIdentifier()
                           ? Call.getCalleeIdentifier()->getName().str()
                           : "unknown")
                   << "'\n";
      llvm::errs() << "[EDSL][AP_EVAL] Origin: " << (const void *)Origin
                   << "\n";
      llvm::errs() << "[EDSL][AP_EVAL] Total APs registered: "
                   << APMatchers.size() << "\n";
    }

    if (!Origin) {
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][AP_EVAL] No origin expression, returning empty "
                        "matches\n";
      }
      return matchingAPs;
    }

    // Use proper ASTMatcher evaluation
    ASTContext &Ctx = C.getASTContext();

    for (const auto &apMatcher : APMatchers) {
      int apNodeId = apMatcher.first;
      const auto &matcher = apMatcher.second;

      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][AP_EVAL] Evaluating AP " << apNodeId
                     << " against call event\n";
        llvm::errs() << "[EDSL][AP_EVAL]   AP " << apNodeId
                     << " represents a formula node\n";
      }

      bool matched = false;
      if (matcher) {
        // Use proper ASTMatcher evaluation with the match function
        // Convert DynTypedMatcher to appropriate typed matcher for evaluation
        if (matcher->canConvertTo<Stmt>()) {
          auto stmtMatcher = matcher->convertTo<Stmt>();
          auto results = clang::ast_matchers::match(stmtMatcher, *Origin, Ctx);
          matched = !results.empty();

          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][AP_EVAL]   Stmt matcher evaluation: "
                         << (matched ? "MATCHED" : "NO MATCH")
                         << " (results: " << results.size() << ")\n";
          }
        } else if (matcher->canConvertTo<Decl>()) {
          // For Decl matchers, we need to check if the origin is a DeclStmt
          if (const auto *DS = dyn_cast<DeclStmt>(Origin)) {
            for (const auto *D : DS->decls()) {
              auto declMatcher = matcher->convertTo<Decl>();
              auto results = clang::ast_matchers::match(declMatcher, *D, Ctx);
              if (!results.empty()) {
                matched = true;
                break;
              }
            }
          }

          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][AP_EVAL]   Decl matcher evaluation: "
                         << (matched ? "MATCHED" : "NO MATCH") << "\n";
          }
        } else {
          // For other types, we need to use the MatchFinder directly
          // This is a more complex approach but necessary for DynTypedMatcher
          clang::ast_matchers::MatchFinder finder;
          clang::ast_matchers::internal::CollectMatchesCallback callback;

          // Use addDynamicMatcher which accepts DynTypedMatcher
          if (finder.addDynamicMatcher(*matcher, &callback)) {
            clang::DynTypedNode dynNode = clang::DynTypedNode::create(*Origin);
            finder.match(dynNode, Ctx);
            matched = !callback.Nodes.empty();

            if (edslDebugEnabled()) {
              llvm::errs()
                  << "[EDSL][AP_EVAL]   DynTypedNode matcher evaluation: "
                  << (matched ? "MATCHED" : "NO MATCH")
                  << " (results: " << callback.Nodes.size() << ")\n";
            }
          } else {
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL][AP_EVAL]   Failed to add DynTypedMatcher "
                              "to MatchFinder\n";
            }
          }
        }
      } else {
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][AP_EVAL] ✗ AP " << apNodeId
                       << " has no matcher\n";
        }
      }

      if (matched) {
        matchingAPs.push_back(apNodeId);
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][AP_EVAL] ✓ AP " << apNodeId
                       << " MATCHED call event\n";
        }
      } else {
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][AP_EVAL] ✗ AP " << apNodeId
                       << " did not match call event\n";
        }
      }
    }

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][AP_EVAL] Total matching APs: "
                   << matchingAPs.size() << "\n";
      if (!matchingAPs.empty()) {
        llvm::errs() << "[EDSL][AP_EVAL] Matching AP IDs: [";
        for (size_t i = 0; i < matchingAPs.size(); ++i) {
          if (i > 0)
            llvm::errs() << ", ";
          llvm::errs() << matchingAPs[i];
        }
        llvm::errs() << "]\n";
      }
    }

    return matchingAPs;
  }

  // Check if we have binding information for an AP
  bool hasBindingInfo(int apNodeId) const {
    return APBindings.find(apNodeId) != APBindings.end();
  }

  // Get all symbol names for an AP
  std::vector<std::string> getSymbolNamesForAP(int apNodeId) const {
    std::vector<std::string> symbolNames;
    auto apIt = APBindings.find(apNodeId);
    if (apIt != APBindings.end()) {
      for (const auto &symbolBinding : apIt->second) {
        symbolNames.push_back(symbolBinding.first);
      }
    }
    return symbolNames;
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

  // (Removed unused getStructuralInfo)

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
  const LTLFormulaNode *
  findNearestDiagnosticAncestor(const LTLFormulaNode *node) const {
    const LTLFormulaNode *cur = node;
    while (cur) {
      if (!cur->DiagnosticLabel.empty())
        return cur;
      cur = cur->Parent;
    }
    return nullptr;
  }

  // (Removed unused generateAutomaton)

  // Extract binding information for event creation
  void populateAPDrivenEventCreator(APDrivenEventCreator &creator) const {
    if (!RootFormula) {
      return;
    }

    extractAPBindings(RootFormula, creator);
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

  void extractAPBindings(const std::shared_ptr<LTLFormulaNode> &node,
                         APDrivenEventCreator &creator) const {
    if (!node)
      return;

    // If this is an atomic node with a binding, register it as an AP
    if (!node->Binding.SymbolName.empty()) {
      creator.registerAPBinding(node->NodeID, node->Binding.SymbolName,
                                node->Binding.Type);

      // If it has a matcher, register it for event matching
      if (node->HasCallMatcher) {
        auto matcher = node->getMatcher();
        if (matcher) {
          creator.registerAPMatcher(node->NodeID, matcher);
        }
      }
    }

    // Recursively process children
    for (const auto &child : node->Children) {
      extractAPBindings(child, creator);
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
// Specific events per checker callback
struct PostCallEvent {
  std::string FunctionName;
  std::string SymbolName; // DSL variable name
  SymbolRef Symbol;       // Return value symbol
  SourceLocation Location;
  const Stmt *OriginExpr;     // call expr
  BindingType DerivedBinding; // Expect ReturnValue
};

struct PreCallEvent {
  std::string FunctionName;
  std::string SymbolName; // DSL variable name
  SymbolRef Symbol;       // Parameter symbol
  SourceLocation Location;
  const Stmt *OriginExpr;     // call expr
  BindingType DerivedBinding; // Expect FirstParameter / NthParameter
};

struct DeadSymbolsEvent {
  std::string SymbolName; // DSL variable name if known
  SymbolRef Symbol;
};

struct EndFunctionEvent {};
struct EndAnalysisEvent {};

struct PointerEscapeEvent {
  std::string SymbolName;
  SymbolRef Symbol;
};

struct BindEvent {
  std::string SymbolName;
  SymbolRef Symbol;
  const MemRegion *BoundRegion;
  const Stmt *StoreExpr;
};

using EventAny =
    llvm::PointerUnion<const PostCallEvent *, const PreCallEvent *,
                       const DeadSymbolsEvent *, const EndFunctionEvent *,
                       const EndAnalysisEvent *, const PointerEscapeEvent *,
                       const BindEvent *>;

// Backward-compatible generic event and type (kept for internal use)
enum class EventType {
  PostCall,
  PreCall,
  DeadSymbols,
  EndFunction,
  EndAnalysis,
  PointerEscape,
  Bind
};

struct GenericEvent {
  EventType Type;
  std::string FunctionName;
  std::string SymbolName;
  SymbolRef Symbol;
  SourceLocation Location;
  const Stmt *OriginExpr;
  BindingType DerivedBinding;
  const MemRegion *BoundRegion;

  GenericEvent(EventType t, const std::string &func, const std::string &sym,
               SymbolRef s, SourceLocation loc, const Stmt *Origin = nullptr,
               BindingType Derived = BindingType::ReturnValue,
               const MemRegion *BR = nullptr)
      : Type(t), FunctionName(func), SymbolName(sym), Symbol(s), Location(loc),
        OriginExpr(Origin), DerivedBinding(Derived), BoundRegion(BR) {}
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
// (Removed unused MonitorAutomaton legacy class)

// (Removed unused PatternMatcher and SymbolTracker helpers)

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

// Example: Mutex Lock/Unlock Property // This demonstrates how the framework
// can be used for other temporal properties
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