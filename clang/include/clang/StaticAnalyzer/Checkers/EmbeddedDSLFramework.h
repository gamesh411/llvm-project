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
#include <sstream>
#include <string>
#include <vector>

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
struct LTLFormulaNode;

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
  std::string BindingName;
  int ParameterIndex;

  SymbolBinding(BindingType Type, const std::string &BindingName,
                int ParameterIndex = 0)
      : Type(Type), BindingName(BindingName), ParameterIndex(ParameterIndex) {}
};

// Base class for LTL formula nodes
struct LTLFormulaNode {
  LTLNodeType Type;
  std::string DiagnosticLabel;
  std::vector<std::shared_ptr<LTLFormulaNode>> Children;
  int NodeID;
  LTLFormulaNode *Parent;

  LTLFormulaNode(LTLNodeType t, const std::string &label = "")
      : Type(t), DiagnosticLabel(label), Children(), NodeID(nextNodeID()),
        Parent(nullptr) {}

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

  virtual std::string toString() const = 0;
  virtual std::string getStructuralInfo() const = 0;

  virtual ~LTLFormulaNode() = default;
};

// Atomic proposition node (function calls, variables)
struct AtomicNode : public LTLFormulaNode {
  std::shared_ptr<clang::ast_matchers::StatementMatcher> Matcher;
  std::optional<SymbolBinding> Binding;

  AtomicNode(const clang::ast_matchers::StatementMatcher &SM,
             const SymbolBinding &binding)
      : LTLFormulaNode(LTLNodeType::Atomic),
        Matcher(std::make_shared<clang::ast_matchers::StatementMatcher>(SM)),
        Binding(binding) {}

  std::string toString() const override {
    std::stringstream result;
    result << "Atomic(";
    if (Binding) {
      result << "Binding: " << (int)Binding->Type
             << ", Name: " << Binding->BindingName
             << ", Index: " << Binding->ParameterIndex;
    }
    if (!DiagnosticLabel.empty()) {
      result << " [" << DiagnosticLabel << "]";
    }
    return result.str();
  }

  std::string getStructuralInfo() const override { return toString(); }
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
// inline std::shared_ptr<LTLFormulaNode> Call(const std::string &funcName,
//                                            const SymbolBinding &binding) {
//  return std::make_shared<AtomicNode>(funcName, binding);
// }

// Overload: accept a matcher; ignore function name entirely in this case.
// Removed DynTypedMatcher overloads in favor of StatementMatcher to comply with
// the LibASTMatchers MatchFinder calling conventions.

inline std::shared_ptr<LTLFormulaNode>
Calling(const clang::ast_matchers::StatementMatcher &Matcher,
        const SymbolBinding &Binding) {
  return std::make_shared<AtomicNode>(Matcher, Binding);
}

inline std::shared_ptr<LTLFormulaNode>
Called(const clang::ast_matchers::StatementMatcher &Matcher,
       const SymbolBinding &Binding) {
  return std::make_shared<AtomicNode>(Matcher, Binding);
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
} // namespace DSL

class LTLFormula {
  std::shared_ptr<LTLFormulaNode> RootNode;

public:
  LTLFormula() = default;

  void setFormula(std::shared_ptr<LTLFormulaNode> formula) {
    RootNode = formula;
  }

  std::string getFormulaString() const {
    return RootNode ? RootNode->toString() : "";
  }

  const LTLFormulaNode *getRootNode() const { return RootNode.get(); }

  const LTLFormulaNode *getNodeByID(int id) const {
    const auto findNodeByIdDFS = [](const LTLFormulaNode *node,
                                    int id) -> const LTLFormulaNode * {
      const auto impl = [](auto &&self, const LTLFormulaNode *node,
                           int id) -> const LTLFormulaNode * {
        if (!node)
          return nullptr;
        if (node->NodeID == id)
          return node;
        for (const auto &child : node->Children) {
          auto result = self(self, std::as_const(child).get(), id);
          if (result)
            return result;
        }
        return nullptr;
      };
      return impl(impl, node, id);
    };
    return findNodeByIdDFS(RootNode.get(), id);
  };

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
};

} // namespace dsl
} // namespace ento
} // namespace clang

#endif // LLVM_CLANG_STATICANALYZER_CHECKERS_EMBEDDEDDSLFRAMEWORK_H