#include "EmbeddedDSLSpot.h"
#include "spot/twaalgos/postproc.hh"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <assert.h>
#include <initializer_list>
#include <iostream>
#include <spot/tl/formula.hh>
#include <spot/tl/parse.hh>
#include <spot/twaalgos/translate.hh>
#include <utility>
namespace clang::ento {
class CheckerBase;
}

// TODO: check if this folding set trait Profile function can be removed
namespace llvm {
template <> struct FoldingSetTrait<std::string> {
  static void Profile(const std::string &X, FoldingSetNodeID &ID) {
    ID.AddString(X);
  }
};
} // namespace llvm

// Define all GDM traits in this translation unit to avoid
// multiple definition issues across translation units
REGISTER_MAP_WITH_PROGRAMSTATE(AutomatonStateForSymbol,
                               ::clang::ento::SymbolRef,
                               ::clang::ento::dsl::AutomatonStateID)
namespace clang::ento::dsl {
ProgramStateRef setAutomatonStateForSymbol(ProgramStateRef State, SymbolRef Sym,
                                           AutomatonStateID StateValue) {
  return State->set<AutomatonStateForSymbol>(Sym, StateValue);
}

const AutomatonStateID *getAutomatonStateForSymbol(ProgramStateRef State,
                                                   SymbolRef Sym) {
  return State->get<AutomatonStateForSymbol>(Sym);
}

ProgramStateRef removeAutomatonStateForSymbol(ProgramStateRef State,
                                              SymbolRef Sym) {
  return State->remove<AutomatonStateForSymbol>(Sym);
}
} // namespace clang::ento::dsl

REGISTER_MAP_WITH_PROGRAMSTATE(BindingVarForSymbol, ::clang::ento::SymbolRef,
                               ::clang::ento::dsl::BindingVarID)

namespace clang::ento::dsl {
ProgramStateRef setBindingVarForSymbol(ProgramStateRef State, SymbolRef Sym,
                                       BindingVarID VarID) {
  return State->set<BindingVarForSymbol>(Sym, VarID);
}

const BindingVarID *getBindingVarForSymbol(ProgramStateRef State,
                                           SymbolRef Sym) {
  return State->get<BindingVarForSymbol>(Sym);
}

ProgramStateRef removeBindingVarForSymbol(ProgramStateRef State,
                                          SymbolRef Sym) {
  return State->remove<BindingVarForSymbol>(Sym);
}
} // namespace clang::ento::dsl

namespace {

using namespace ::clang;
using namespace ento;
using namespace dsl;

// Prefer the smallest (deepest) labeled node in a subtree, with optional
// preference for specific temporal/boolean node types.
static std::string
selectLabelFromSubtree(const LTLFormulaNode *root,
                       std::initializer_list<LTLNodeType> PreferredTypesList) {
  if (!root)
    return std::string();
  llvm::SmallVector<LTLNodeType, 4> PreferredTypes(PreferredTypesList.begin(),
                                                   PreferredTypesList.end());
  struct Candidate {
    const LTLFormulaNode *Node;
    int Depth;
  };
  std::vector<Candidate> Preferred, Any;
  const std::function<void(const LTLFormulaNode *, int)> depthFirstSearch =
      [&](const LTLFormulaNode *Node, int Depth) {
        if (!Node)
          return;
        if (!Node->DiagnosticLabel.empty()) {
          bool IsPreferred =
              std::find(PreferredTypes.begin(), PreferredTypes.end(),
                        Node->Type) != PreferredTypes.end();
          if (IsPreferred)
            Preferred.push_back({Node, Depth});
          Any.push_back({Node, Depth});
        }
        for (const auto &Child : Node->Children)
          depthFirstSearch(Child.get(), Depth + 1);
      };
  depthFirstSearch(root, 0);
  auto pickDeepest =
      [](const std::vector<Candidate> &Candidates) -> const LTLFormulaNode * {
    const LTLFormulaNode *BestMatch = nullptr;
    int BestDepth = -1;
    for (const auto &Candidate : Candidates) {
      if (Candidate.Depth > BestDepth) {
        BestDepth = Candidate.Depth;
        BestMatch = Candidate.Node;
      }
    }
    return BestMatch;
  };
  if (!Preferred.empty()) {
    if (auto *Node = pickDeepest(Preferred))
      return Node->DiagnosticLabel;
  }
  if (!Any.empty()) {
    if (auto *Node = pickDeepest(Any))
      return Node->DiagnosticLabel;
  }
  return std::string();
}

static std::string getAPNameFromNodeID(FormulaNodeID NodeID) {
  assert(NodeID >= 0 && "Node ID must be non-negative");
  return "ap_" + std::to_string(NodeID);
}

static FormulaNodeID getNodeIDFromAPName(const std::string &APName) {
  assert(APName.length() >= 3 && APName.substr(0, 3) == "ap_" &&
         "AP name must start with 'ap_'");
  return std::stoi(APName.substr(3));
}

static std::string buildSpotFormulaString(const LTLFormulaNode *Node) {
  if (!Node)
    return "1"; // true

  switch (Node->Type) {
  case LTLNodeType::Atomic: {
    const std::string APName = getAPNameFromNodeID(Node->NodeID);
    // Capture values needed for evaluation
    return APName;
  }
  case LTLNodeType::And:
    return std::string("(") + buildSpotFormulaString(Node->Children[0].get()) +
           " & " + buildSpotFormulaString(Node->Children[1].get()) + ")";
  case LTLNodeType::Or:
    return std::string("(") + buildSpotFormulaString(Node->Children[0].get()) +
           " | " + buildSpotFormulaString(Node->Children[1].get()) + ")";
  case LTLNodeType::Implies:
    return std::string("(") + buildSpotFormulaString(Node->Children[0].get()) +
           " -> " + buildSpotFormulaString(Node->Children[1].get()) + ")";
  case LTLNodeType::Not:
    return std::string("!(") + buildSpotFormulaString(Node->Children[0].get()) +
           ")";
  case LTLNodeType::Globally:
    return std::string("G(") + buildSpotFormulaString(Node->Children[0].get()) +
           ")";
  case LTLNodeType::Eventually:
    return std::string("F(") + buildSpotFormulaString(Node->Children[0].get()) +
           ")";
  case LTLNodeType::Next:
    return std::string("X(") + buildSpotFormulaString(Node->Children[0].get()) +
           ")";
  case LTLNodeType::Until:
    return std::string("(") + buildSpotFormulaString(Node->Children[0].get()) +
           " U " + buildSpotFormulaString(Node->Children[1].get()) + ")";
  case LTLNodeType::Release:
    return std::string("(") + buildSpotFormulaString(Node->Children[0].get()) +
           " R " + buildSpotFormulaString(Node->Children[1].get()) + ")";
  }
  llvm_unreachable("Invalid LTLNodeType");
}

} // namespace

DSLMonitor::DSLMonitor(const CheckerBase *ContainingChecker,
                       std::unique_ptr<PropertyDefinition> Property)
    : ContainingChecker(ContainingChecker), Property(std::move(Property)) {

  const LTLFormulaNode *root = Property->Formula.getRootNode();
  std::string infix = buildSpotFormulaString(root);
  if (infix.empty())
    infix = "G 1";

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][SPOT] PSL formula: " << infix << "\n";
  }

  spot::parsed_formula pf = spot::parse_infix_psl(infix);
  if (pf.format_errors(std::cerr)) {
    llvm_unreachable("Failed to parse formula");
  }

  spot::translator trans;
  trans.set_pref(spot::postprocessor::Deterministic);
  auto monitor = trans.run(pf.f);

  // TODO: Implement
}

// Event handlers work directly with individual event types
// No more generic CheckerEvent - each handler processes its specific event type
void DSLMonitor::handleEvent(PostCallEvent E) {
  // TODO: Implement direct handling without CheckerEvent
  (void)E;
}

void DSLMonitor::handleEvent(PreCallEvent E) {
  // TODO: Implement direct handling without CheckerEvent
  (void)E;
}

void DSLMonitor::handleEvent(DeadSymbolsEvent E) {
  // TODO: Implement direct handling without CheckerEvent
  (void)E;
}

void DSLMonitor::handleEvent(EndAnalysisEvent E) {
  // TODO: Implement direct handling without CheckerEvent
  (void)E;
}
