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

// Generic symbol usage context in temporal formulas
enum class SymbolContext {
  Creation,    // Symbol is created (return value, acquisition)
  Destruction, // Symbol is destroyed (parameter, release)
  Validation,  // Symbol is validated (condition check)
  Temporal,    // Symbol appears in temporal operators (F, G, U, etc.)
  CrossContext // Symbol appears in multiple contexts
};

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

  std::unique_ptr<LTLAutomaton> generateAutomaton() const {
    if (!RootFormula) {
      return nullptr;
    }

    LTLParser parser(RootFormula);
    return parser.generateAutomaton();
  }

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
class MonitorAutomaton {
  std::string PropertyName;
  LTLFormulaBuilder FormulaBuilder;
  const CheckerBase *Checker;
  APDrivenEventCreator EventCreator;
  // SPOT-backed monitor is owned in the checker TU to avoid header cycles

public:
  struct NonErrorResult {
    ProgramStateRef State;
    const NoteTag *NoteTag;
    NonErrorResult(ProgramStateRef S, const clang::ento::NoteTag *NT = nullptr)
        : State(S), NoteTag(NT) {}
  };

  struct DeferredErrorResult {
    std::string Message;
    std::string BugTypeName;
    std::string BugTypeCategory;
    SymbolRef Symbol;
    DeferredErrorResult(const std::string &Msg, const std::string &TypeName,
                        const std::string &TypeCategory,
                        SymbolRef Sym = nullptr)
        : Message(Msg), BugTypeName(TypeName), BugTypeCategory(TypeCategory),
          Symbol(Sym) {}
  };

  using EventResult = std::variant<NonErrorResult, DeferredErrorResult>;

  MonitorAutomaton(std::unique_ptr<PropertyDefinition> prop,
                   const CheckerBase *C)
      : PropertyName(prop->getPropertyName()),
        FormulaBuilder(prop->getFormulaBuilder()), Checker(C) {
    // Populate AP-driven event creator with formula information
    FormulaBuilder.populateAPDrivenEventCreator(EventCreator);
  }

  // New method that returns results instead of calling addTransition directly
  llvm::SmallVector<EventResult, 2> handleEvent(const GenericEvent &event,
                                                ProgramStateRef State,
                                                SValBuilder &SVB,
                                                SymbolManager &SymMgr);

  void handleEvent(const GenericEvent &event, CheckerContext &C) {
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL] handleEvent: type=";
      switch (event.Type) {
      case EventType::PostCall:
        llvm::errs() << "PostCall";
        break;
      case EventType::PreCall:
        llvm::errs() << "PreCall";
        break;
      case EventType::DeadSymbols:
        llvm::errs() << "DeadSymbols";
        break;
      case EventType::EndFunction:
        llvm::errs() << "EndFunction";
        break;
      case EventType::EndAnalysis:
        llvm::errs() << "EndAnalysis";
        break;
      case EventType::PointerEscape:
        llvm::errs() << "PointerEscape";
        break;
      case EventType::Bind:
        llvm::errs() << "Bind";
        break;
      }
      llvm::errs() << ", fn=" << event.FunctionName
                   << ", sym=" << event.SymbolName << "\n";
    }
    // Generic, checker-agnostic lifecycle modeling driven by bindings.
    // This block purposefully contains no malloc/free specific strings.
    ProgramStateRef State = C.getState();

    switch (event.Type) {
    case EventType::PostCall: {
      if (event.Symbol && !event.SymbolName.empty()) {
        // Treat a PostCall bound to a ReturnValue as a creation event
        BindingType BT = event.DerivedBinding;
        if (BT == BindingType::ReturnValue) {
          // Perform splitting only if the formula actually uses IsNonNull(x)
          if (isSymbolUsedInIsNonNull(event.SymbolName)) {
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL] create: " << event.FunctionName << "("
                           << event.SymbolName << ") -> split on non-null\n";
            }
            SValBuilder &SVB = C.getSValBuilder();
            SVal SymV = SVB.makeLoc(event.Symbol);
            QualType PtrTy = event.Symbol->getType();
            SVal Null = SVB.makeZeroVal(PtrTy);
            SVal NE = SVB.evalBinOp(C.getState(), BO_NE, SymV, Null,
                                    C.getASTContext().BoolTy);
            if (auto D = NE.getAs<DefinedSVal>()) {
              ProgramStateRef STrue, SFalse;
              std::tie(STrue, SFalse) =
                  C.getConstraintManager().assumeDual(C.getState(), *D);
              if (STrue) {
                auto St = dsl::setSymbolState(STrue, event.Symbol,
                                              ::SymbolState::Active);
                // Remember the formula variable name and track symbol
                St = dsl::setGenericSymbolMap(St, event.Symbol,
                                              event.SymbolName);
                St = dsl::addTrackedSymbol(St, event.Symbol);
                if (edslDebugEnabled()) {
                  unsigned cnt = dsl::getTrackedSymbolCount(St);
                  llvm::errs()
                      << "[EDSL] track: add TrackedSymbols sym_id="
                      << event.Symbol->getSymbolID() << " name='"
                      << event.SymbolName
                      << "' predNode=" << (const void *)C.getPredecessor()
                      << " tracked_count=" << cnt << "\n";
                }
                // Note-only transition for correlation
                std::string internal =
                    "sym_" + std::to_string(event.Symbol->getSymbolID());
                std::string var = event.SymbolName.empty() ? std::string("x")
                                                           : event.SymbolName;
                std::string note =
                    std::string("symbol \"") + var +
                    "\" is bound here (internal symbol: " + internal + ")";
                const NoteTag *NT = C.getNoteTag([note]() { return note; });
                C.addTransition(St, NT);
                // Ensure the subsequent operations use the latest state on this
                // path. For CSA, addTransition creates a new node; subsequent
                // modeling will observe it via C.getState() on the next
                // callback.
              }
              if (SFalse) {
                auto Sf = dsl::setSymbolState(SFalse, event.Symbol,
                                              ::SymbolState::Uninitialized);
                Sf = dsl::setGenericSymbolMap(Sf, event.Symbol,
                                              event.SymbolName);
                C.addTransition(Sf);
              }
              return; // handled both branches
            }
          }
          // If no IsNonNull AP in formula, avoid forcing splits
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL] create: " << event.FunctionName << "("
                         << event.SymbolName
                         << ") -> no split (no IsNonNull AP)\n";
          }
          // Lightweight bookkeeping only
          State = dsl::setSymbolState(State, event.Symbol,
                                      ::SymbolState::Uninitialized);
          State =
              dsl::setGenericSymbolMap(State, event.Symbol, event.SymbolName);
          C.addTransition(State);
          return;
        }
      }
      break;
    }
    case EventType::PreCall: {
      if (event.Symbol && !event.SymbolName.empty()) {
        // Treat a PreCall bound to a parameter as a destruction event
        BindingType BT = event.DerivedBinding;
        if (BT == BindingType::FirstParameter ||
            BT == BindingType::NthParameter) {
          const ::SymbolState *CurPtr =
              dsl::getSymbolState(State, event.Symbol);
          ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
          // If Potential and IsNonNull present for symbol, split on non-null
          if (Cur == ::SymbolState::Uninitialized &&
              isSymbolUsedInIsNonNull(event.SymbolName)) {
            SValBuilder &SVB = C.getSValBuilder();
            SVal SymV = SVB.makeLoc(event.Symbol);
            QualType PtrTy = event.Symbol->getType();
            SVal Null = SVB.makeZeroVal(PtrTy);
            SVal NE = SVB.evalBinOp(C.getState(), BO_NE, SymV, Null,
                                    C.getASTContext().BoolTy);
            if (auto D = NE.getAs<DefinedSVal>()) {
              ProgramStateRef STrue, SFalse;
              std::tie(STrue, SFalse) =
                  C.getConstraintManager().assumeDual(C.getState(), *D);
              if (STrue) {
                auto Sa = dsl::setSymbolState(STrue, event.Symbol,
                                              ::SymbolState::Active);
                Sa = dsl::setGenericSymbolMap(Sa, event.Symbol,
                                              event.SymbolName);
                Sa = dsl::addTrackedSymbol(Sa, event.Symbol);
                // Perform destruction on the non-null branch: bookkeeping only
                Sa = dsl::setSymbolState(Sa, event.Symbol,
                                         ::SymbolState::Inactive);
                Sa = dsl::removeGenericSymbolMap(Sa, event.Symbol);
                Sa = dsl::removeTrackedSymbol(Sa, event.Symbol);
                if (edslDebugEnabled()) {
                  llvm::errs()
                      << "[EDSL] destroy: " << event.FunctionName << "("
                      << event.SymbolName << ") -> Inactive (split)\n";
                }
                C.addTransition(Sa);
              }
              if (SFalse) {
                // Null branch: do nothing for destruction
                C.addTransition(SFalse);
              }
              return;
            }
          }
          const ::SymbolState *CurPtr2 =
              dsl::getSymbolState(C.getState(), event.Symbol);
          ::SymbolState Cur2 =
              CurPtr2 ? *CurPtr2 : ::SymbolState::Uninitialized;
          if (Cur2 == ::SymbolState::Active) {
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL] destroy: " << event.FunctionName << "("
                           << event.SymbolName << ") -> Inactive\n";
            }
            State = dsl::setSymbolState(State, event.Symbol,
                                        ::SymbolState::Inactive);
            State = dsl::removeGenericSymbolMap(State, event.Symbol);
            State = dsl::removeTrackedSymbol(State, event.Symbol);
            C.addTransition(State);
          }
        }
      }
      break;
    }
    case EventType::DeadSymbols: {
      // Intentionally no-op here; leaks reported at EndFunction for better
      // location
      break;
    }
    case EventType::PointerEscape: {
      if (event.Symbol) {
        // Transfer ownership out of this frame: do not report leak here
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL] escape: dropping PendingLeak obligation for "
                       << event.SymbolName << "\n";
        }
        State = dsl::removeTrackedSymbol(State, event.Symbol);
        C.addTransition(State);
      }
      break;
    }
    case EventType::Bind: {
      // Handle region binding: remember region only; no splitting here
      if (event.Symbol) {
        ProgramStateRef Cur = State;
        if (event.BoundRegion)
          Cur = dsl::setSymbolToRegionMap(Cur, event.Symbol, event.BoundRegion);
        if (edslDebugEnabled())
          llvm::errs() << "[EDSL][BIND] record region only sym_id="
                       << event.Symbol->getSymbolID() << " var='"
                       << event.SymbolName << "'\n";
        C.addTransition(Cur);
      }
      break;
    }
    case EventType::EndFunction: {
      // No direct diagnostics here; EndFunction does not imply unreachability.
      C.addTransition(State);
      break;
    }
    case EventType::EndAnalysis: {
      // Enumerate any tracked active symbols and forward EndAnalysis events.
      for (auto Sym : dsl::getTrackedSymbols(State)) {
        const ::SymbolState *CurPtr = dsl::getSymbolState(State, Sym);
        ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
        if (Cur == ::SymbolState::Active) {
          std::string name = "sym_" + std::to_string(Sym->getSymbolID());
          (void)
              name; // naming retained for SPOT AP evaluation in the checker TU
        }
      }
      C.addTransition(State);
      break;
    }
    }
  }

  std::string getPropertyName() const { return PropertyName; }
  LTLFormulaBuilder getFormulaBuilder() const { return FormulaBuilder; }
  bool isSymbolUsedInIsNonNull(const std::string &symbolName) const {
    const LTLFormulaNode *root = FormulaBuilder.getRootNode();
    std::function<bool(const LTLFormulaNode *)> dfs =
        [&](const LTLFormulaNode *n) -> bool {
      if (!n)
        return false;
      if (n->Type == LTLNodeType::Atomic) {
        if (n->Binding.SymbolName == symbolName &&
            isNonNullBinding(n->Binding.Type))
          return true;
      }
      for (const auto &ch : n->Children)
        if (dfs(ch.get()))
          return true;
      return false;
    };
    return dfs(root);
  }

  // Extract atomic propositions from an event
  std::set<std::string> extractPropositions(const GenericEvent &event,
                                            CheckerContext &C) const {
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
      std::string internalSymbolName =
          "sym_" + std::to_string(event.Symbol->getSymbolID());
      enhancedDiagnostic += " (internal symbol: " + internalSymbolName + ")";
    }

    auto R = std::make_unique<PathSensitiveBugReport>(*BT, enhancedDiagnostic,
                                                      ErrorNode);
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
    std::string internalSymbolName =
        "sym_" + std::to_string(event.Symbol->getSymbolID());
    std::string noteMessage =
        "symbol \"" + formulaVar +
        "\" is bound here (internal symbol: " + internalSymbolName + ")";

    // Create a note using getNoteTag
    const NoteTag *noteTag =
        C.getNoteTag([noteMessage]() { return noteMessage; });
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
    C.addTransition(dsl::setGenericSymbolMap(State, sym, value));
  }

  static std::string getSymbolValue(ProgramStateRef State, SymbolRef sym) {
    if (const std::string *value = dsl::getGenericSymbolMap(State, sym)) {
      return *value;
    }
    return "";
  }

  static void removeSymbol(ProgramStateRef State, SymbolRef sym,
                           CheckerContext &C) {
    C.addTransition(dsl::removeGenericSymbolMap(State, sym));
  }

  static bool hasSymbol(ProgramStateRef State, SymbolRef sym) {
    return dsl::hasGenericSymbolMap(State, sym);
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