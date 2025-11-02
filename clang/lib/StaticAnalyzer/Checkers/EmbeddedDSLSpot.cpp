#include "EmbeddedDSLSpot.h"
#include "spot/twaalgos/postproc.hh"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/GraphTraits.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <assert.h>
#include <initializer_list>
#include <iostream>
#include <set>
#include <spot/tl/formula.hh>
#include <spot/tl/ltlf.hh>
#include <spot/tl/parse.hh>
#include <spot/tl/print.hh>
#include <spot/twa/bdddict.hh>
#include <spot/twaalgos/ltlf2dfa.hh>
#include <spot/twaalgos/remprop.hh>
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

REGISTER_MAP_WITH_PROGRAMSTATE(TraceSemanticsAPState,
                               ::clang::ento::dsl::AtomicPropositionID, bool)

namespace clang::ento::dsl {
ProgramStateRef setTraceSemanticsAPState(ProgramStateRef State,
                                         AtomicPropositionID APID,
                                         bool StateValue) {
  return State->set<TraceSemanticsAPState>(APID, StateValue);
}

const bool *getTraceSemanticsAPState(ProgramStateRef State,
                                     AtomicPropositionID APID) {
  return State->get<TraceSemanticsAPState>(APID);
}

ProgramStateRef removeTraceSemanticsAPState(ProgramStateRef State,
                                            AtomicPropositionID APID) {
  return State->remove<TraceSemanticsAPState>(APID);
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

// Traverse formula tree to extract binding variable information
static void
extractBindingVariables(const LTLFormulaNode *Node,
                        std::map<FormulaNodeID, std::optional<BindingVarID>>
                            &BindingVarForFormulaNode,
                        std::map<BindingVarID, std::vector<FormulaNodeID>>
                            &FormulaNodesForBindingVar,
                        std::set<FormulaNodeID> &VisitedNodes) {
  if (!Node)
    return;

  // Skip if we've already processed this node (avoid duplicates in DAG)
  if (VisitedNodes.find(Node->NodeID) != VisitedNodes.end()) {
    return;
  }
  VisitedNodes.insert(Node->NodeID);

  if (Node->Type == LTLNodeType::Atomic) {
    const AtomicNode *Atomic = static_cast<const AtomicNode *>(Node);
    if (Atomic->Binding.has_value()) {
      const BindingVarID &BindingName = Atomic->Binding.value().BindingName;
      BindingVarForFormulaNode[Node->NodeID] = BindingName;

      // Only add to vector if not already present (avoid duplicates)
      auto &nodeList = FormulaNodesForBindingVar[BindingName];
      if (std::find(nodeList.begin(), nodeList.end(), Node->NodeID) ==
          nodeList.end()) {
        nodeList.push_back(Node->NodeID);
      }
    } else {
      BindingVarForFormulaNode[Node->NodeID] = std::nullopt;
    }
  }

  // Recurse into children
  for (const auto &Child : Node->Children) {
    extractBindingVariables(Child.get(), BindingVarForFormulaNode,
                            FormulaNodesForBindingVar, VisitedNodes);
  }
}

// Helper: Extract AP IDs that appear in a BDD condition
// Returns a set of AtomicPropositionID that are relevant to the BDD
// A variable is relevant if it appears in the support of the condition
std::set<AtomicPropositionID>
extractAPsFromBDD(bdd bddCond,
                  const std::map<AtomicPropositionID, bdd> &BDDForAP) {
  std::set<AtomicPropositionID> relevantAPs;

  // Get the support set (BDD representing all variables that affect the
  // condition)
  bdd support = bdd_support(bddCond);

  // Check each AP's BDD variable
  for (const auto &[apID, apBDD] : BDDForAP) {
    int apVar = bdd_var(apBDD);
    bdd varBDD = bdd_ithvar(apVar);

    // Check if this variable is in the support:
    // The variable is in support if restricting the condition by the variable
    // produces a different result than restricting by its negation
    // OR if the variable appears in the support BDD
    bdd restrictTrue = bdd_restrict(bddCond, varBDD);
    bdd restrictFalse = bdd_restrict(bddCond, bdd_not(varBDD));

    // If restrictions differ, the variable affects the condition
    if (restrictTrue != restrictFalse) {
      relevantAPs.insert(apID);
    }
  }

  return relevantAPs;
}

// Helper: Find all parent nodes (ancestors) of a given node, including the node
// itself
std::vector<const LTLFormulaNode *>
findAllParentNodes(const LTLFormulaNode *node) {
  std::vector<const LTLFormulaNode *> nodes;
  const LTLFormulaNode *current = node;

  while (current) {
    nodes.push_back(current);
    current = current->Parent;
  }

  return nodes;
}

// Helper: Collect diagnostic labels from formula nodes, prioritizing atomic
// nodes
std::string collectDiagnosticLabels(
    const std::set<AtomicPropositionID> &relevantAPIDs,
    const std::map<AtomicPropositionID, FormulaNodeID> &FormulaNodeForAP,
    const LTLFormula &Formula) {

  std::vector<std::string> atomicLabels;
  std::vector<std::string> parentLabels;

  // Find all formula nodes that contain the relevant APs
  std::set<const LTLFormulaNode *> relevantNodes;

  for (AtomicPropositionID apID : relevantAPIDs) {
    auto it = FormulaNodeForAP.find(apID);
    if (it != FormulaNodeForAP.end()) {
      FormulaNodeID nodeID = it->second;
      const LTLFormulaNode *node = Formula.getNodeByID(nodeID);
      if (node) {
        // Get all ancestors of this node (including itself)
        std::vector<const LTLFormulaNode *> ancestors =
            findAllParentNodes(node);
        relevantNodes.insert(ancestors.begin(), ancestors.end());
      }
    }
  }

  // Collect labels, prioritizing atomic nodes
  for (const LTLFormulaNode *node : relevantNodes) {
    if (!node->DiagnosticLabel.empty()) {
      if (node->Type == LTLNodeType::Atomic) {
        atomicLabels.push_back(node->DiagnosticLabel);
      } else {
        parentLabels.push_back(node->DiagnosticLabel);
      }
    }
  }

  // Prefer atomic node labels (most specific), fall back to parent labels
  if (!atomicLabels.empty()) {
    // If multiple atomic labels, join them
    std::string result = atomicLabels[0];
    for (size_t i = 1; i < atomicLabels.size(); i++) {
      result += "; " + atomicLabels[i];
    }
    return result;
  } else if (!parentLabels.empty()) {
    return parentLabels[0];
  }

  return "Property violation detected";
}

// Helper: Evaluate an AP for a given call event
// Returns (apValue, needsBindingHandling)
std::pair<bool, bool> evaluateAP(const AtomicNode *Atomic,
                                 AtomicPropositionID apID, FormulaNodeID nodeID,
                                 ProgramStateRef &State, const CallEvent &Call,
                                 ASTContext &ASTCtx, const char *EventName) {
  bool apValue = false;
  bool needsBindingHandling = false;

  if (Atomic->IsTraceSemanticsCall) {
    // Check if already evaluated to true in GDM
    const bool *alreadyTrue = getTraceSemanticsAPState(State, apID);
    if (alreadyTrue && *alreadyTrue) {
      // Already evaluated to true - assume it's true
      apValue = true;
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][" << EventName << "] AP " << apID << " (node "
                     << nodeID
                     << ") already true in trace semantics, assuming true\n";
      }
      needsBindingHandling = Atomic->Binding.has_value();
    } else {
      // Not in GDM yet - evaluate matcher
      const Expr *Origin = Call.getOriginExpr();
      if (Origin && Atomic->Matcher) {
        auto Matches = ast_matchers::match(*Atomic->Matcher, *Origin, ASTCtx);
        bool matched = !Matches.empty();
        if (matched) {
          apValue = true;
          // Set trace semantics marker in GDM
          State = setTraceSemanticsAPState(State, apID, true);
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][" << EventName << "] AP " << apID
                         << " (node " << nodeID
                         << ") matched, setting trace semantics marker\n";
          }
        }
        needsBindingHandling = matched && Atomic->Binding.has_value();
      }
    }
  } else {
    // No trace semantics - evaluate matcher directly
    const Expr *Origin = Call.getOriginExpr();
    if (Origin && Atomic->Matcher) {
      auto Matches = ast_matchers::match(*Atomic->Matcher, *Origin, ASTCtx);
      apValue = !Matches.empty();
      needsBindingHandling = apValue && Atomic->Binding.has_value();
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][" << EventName << "] AP " << apID << " (node "
                     << nodeID << ") evaluated to "
                     << (apValue ? "TRUE" : "FALSE") << "\n";
      }
    }
  }

  return {apValue, needsBindingHandling};
}

// Helper: Build BDD valuation from AP valuations
bdd buildBDDValuation(const std::map<AtomicPropositionID, bool> &APValuations,
                      const std::map<AtomicPropositionID, bdd> &BDDForAP,
                      bool alive, const std::optional<bdd> &AliveAPBDD,
                      const char *EventName) {
  bdd valuation = bddtrue;
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][" << EventName
                 << "] Building BDD valuation from AP evaluations:\n";
  }

  // Add "alive" AP
  if (AliveAPBDD.has_value()) {
    if (alive) {
      valuation = bdd_and(valuation, *AliveAPBDD);
      if (edslDebugEnabled()) {
        llvm::errs() << "  alive = TRUE -> BDD var " << bdd_var(*AliveAPBDD)
                     << "\n";
      }
    } else {
      valuation = bdd_and(valuation, bdd_not(*AliveAPBDD));
      if (edslDebugEnabled()) {
        llvm::errs() << "  alive = FALSE -> !BDD var " << bdd_var(*AliveAPBDD)
                     << "\n";
      }
    }
  }

  // Add AP valuations
  for (const auto &[apID, value] : APValuations) {
    bdd apBDD = BDDForAP.at(apID);
    if (value) {
      valuation = bdd_and(valuation, apBDD);
      if (edslDebugEnabled()) {
        llvm::errs() << "  AP " << apID << " = TRUE -> BDD var "
                     << bdd_var(apBDD) << "\n";
      }
    } else {
      valuation = bdd_and(valuation, bdd_not(apBDD));
      if (edslDebugEnabled()) {
        llvm::errs() << "  AP " << apID << " = FALSE -> !BDD var "
                     << bdd_var(apBDD) << "\n";
      }
    }
  }

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][" << EventName
                 << "] BDD valuation built (BDD id: " << valuation.id()
                 << ")\n";
  }

  return valuation;
}

// Helper: Step the automaton based on valuation
// Returns (nextState, foundTransition, violatingEdgeCond)
std::tuple<unsigned, bool, bdd>
stepAutomaton(unsigned currentState, bdd valuation,
              const spot::twa_graph_ptr &SpotGraph, const char *EventName) {
  unsigned nextState = currentState;
  bool foundTransition = false;
  bdd violatingEdgeCond = bddfalse;

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][" << EventName << "] Stepping automaton from state "
                 << currentState
                 << " with valuation (BDD id: " << valuation.id() << ")\n";
    llvm::errs() << "[EDSL][" << EventName << "] Checking outgoing edges:\n";
  }

  for (auto &edge : SpotGraph->out(currentState)) {
    bdd edgeCond = edge.cond;
    unsigned edgeDst = edge.dst;

    bdd restricted = bdd_restrict(edgeCond, valuation);
    int implies = bdd_implies(valuation, edgeCond);

    if (edslDebugEnabled()) {
      llvm::errs() << "  Edge: " << currentState << " -> " << edgeDst
                   << ", condition BDD id: " << edgeCond.id() << "\n";
      llvm::errs() << "    Restricted BDD id: " << restricted.id()
                   << " (bddfalse id: " << bddfalse.id()
                   << ", bddtrue id: " << bddtrue.id() << ")\n";
      llvm::errs() << "    bdd_implies(valuation, edgeCond): " << implies
                   << "\n";
    }

    if (restricted == bddtrue || implies) {
      nextState = edgeDst;
      foundTransition = true;
      violatingEdgeCond = edgeCond; // Track the condition that was satisfied
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][" << EventName
                     << "] ✓ Found matching transition: " << currentState
                     << " -> " << nextState << "\n";
      }
      break;
    } else if (edslDebugEnabled()) {
      llvm::errs() << "    Transition not satisfied\n";
    }
  }

  if (!foundTransition) {
    nextState = currentState;
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][" << EventName
                   << "] No matching transition, staying in state "
                   << currentState << "\n";
    }
  }

  return {nextState, foundTransition, violatingEdgeCond};
}

// Helper: Find ReturnStmt by walking back through predecessors
static const ReturnStmt *findReturnStmt(const ExplodedNode *N) {
  const StackFrameContext *SF = N->getStackFrame();
  const ExplodedNode *Current = N;

  // First, check if the current node itself is a FunctionExitPoint with a
  // ReturnStmt
  const ProgramPoint &CurrentPP = Current->getLocation();
  if (CurrentPP.getStackFrame() == SF) {
    if (std::optional<FunctionExitPoint> FEP =
            CurrentPP.getAs<FunctionExitPoint>()) {
      if (const Stmt *S = FEP->getStmt()) {
        if (const ReturnStmt *RS = dyn_cast<ReturnStmt>(S)) {
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][findReturnStmt] Found ReturnStmt in "
                            "FunctionExitPoint\n";
          }
          return RS;
        }
      }
    }
  }

  // Walk back through predecessors
  while (Current) {
    const ProgramPoint &PP = Current->getLocation();

    if (PP.getStackFrame() == SF) {
      if (std::optional<StmtPoint> SP = PP.getAs<StmtPoint>()) {
        if (const ReturnStmt *RS = dyn_cast<ReturnStmt>(SP->getStmt())) {
          if (edslDebugEnabled()) {
            llvm::errs()
                << "[EDSL][findReturnStmt] Found ReturnStmt in StmtPoint\n";
          }
          return RS;
        }
      } else if (std::optional<CallExitBegin> CEB = PP.getAs<CallExitBegin>()) {
        if (const ReturnStmt *RS = CEB->getReturnStmt()) {
          if (edslDebugEnabled()) {
            llvm::errs()
                << "[EDSL][findReturnStmt] Found ReturnStmt in CallExitBegin\n";
          }
          return RS;
        }
      }
    }

    if (Current->pred_empty())
      break;
    Current = *Current->pred_begin();
  }

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][findReturnStmt] No ReturnStmt found\n";
  }
  return nullptr;
}

// Helper: Report a violation with diagnostic extraction
void reportViolation(
    unsigned nextState, bdd violatingEdgeCond, bool foundTransition,
    const std::map<AtomicPropositionID, bdd> &BDDForAP,
    const std::map<AtomicPropositionID, FormulaNodeID> &FormulaNodeForAP,
    const LTLFormula &Formula, const ExplodedNode *N, BugReporter &BR,
    const CheckerBase *ContainingChecker) {
  // Extract relevant APs from the violating edge condition
  std::set<AtomicPropositionID> relevantAPIDs;
  if (foundTransition && violatingEdgeCond != bddfalse) {
    relevantAPIDs = extractAPsFromBDD(violatingEdgeCond, BDDForAP);
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL]   Relevant APs from edge condition: ";
      for (AtomicPropositionID apID : relevantAPIDs) {
        llvm::errs() << apID << " ";
      }
      llvm::errs() << "\n";
    }
  }

  // Collect diagnostic labels from formula nodes containing relevant APs
  std::string diagnosticMsg =
      collectDiagnosticLabels(relevantAPIDs, FormulaNodeForAP, Formula);

  // Find a good location for the diagnostic
  // For leak violations (end-of-function), prefer return statement or closing
  // brace
  PathDiagnosticLocation Loc;
  const Stmt *S = N->getStmtForDiagnostics();

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][REPORT] Finding location for violation report\n";
    llvm::errs() << "[EDSL][REPORT] getStmtForDiagnostics() returned: "
                 << (S ? "non-null" : "null") << "\n";
    if (S) {
      llvm::errs() << "[EDSL][REPORT] Stmt type: " << S->getStmtClassName()
                   << "\n";
      llvm::errs() << "[EDSL][REPORT] Stmt source range: "
                   << S->getBeginLoc().printToString(BR.getSourceManager())
                   << " - "
                   << S->getEndLoc().printToString(BR.getSourceManager())
                   << "\n";
    }
  }

  if (S) {
    // Check if this is an end-of-function node (FunctionExitPoint)
    // or if we got a CompoundStmt (function body) from getStmtForDiagnostics()
    const ProgramPoint &PP = N->getLocation();
    bool isEndOfFunction = PP.getAs<FunctionExitPoint>().has_value();

    // Also check if S is a CompoundStmt - this might be the function body
    // and we're at end-of-function, so we want to find the return statement
    if (isEndOfFunction || isa<CompoundStmt>(S)) {
      // For end-of-function, prefer ReturnStmt if available
      if (isa<ReturnStmt>(S)) {
        // Already have a ReturnStmt, use it
        Loc = PathDiagnosticLocation(S, BR.getSourceManager(),
                                     N->getLocationContext());
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][REPORT] Using ReturnStmt from "
                          "getStmtForDiagnostics()\n";
        }
      } else if (isa<CompoundStmt>(S)) {
        // Got function body (CompoundStmt), try to find ReturnStmt inside it
        const CompoundStmt *CS = cast<CompoundStmt>(S);
        const ReturnStmt *RS = nullptr;
        // Look for ReturnStmt in the body statements (from last to first for
        // efficiency)
        for (auto I = CS->body_rbegin(), E = CS->body_rend(); I != E; ++I) {
          if (const ReturnStmt *FoundRS = dyn_cast<ReturnStmt>(*I)) {
            RS = FoundRS;
            break;
          }
        }

        if (RS) {
          Loc = PathDiagnosticLocation(RS, BR.getSourceManager(),
                                       N->getLocationContext());
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][REPORT] Found ReturnStmt in CompoundStmt "
                            "body, using it: "
                         << RS->getBeginLoc().printToString(
                                BR.getSourceManager())
                         << "\n";
          }
        } else {
          // No ReturnStmt in body, try to find it via predecessors or use
          // closing brace
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][REPORT] No ReturnStmt in CompoundStmt "
                            "body, trying findReturnStmt()\n";
          }
          S = nullptr; // Fall through to return stmt search
        }
      } else {
        // Other statement type for end-of-function, try to find ReturnStmt in
        // predecessors
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][REPORT] End-of-function node with "
                       << S->getStmtClassName()
                       << ", trying to find ReturnStmt\n";
        }
        S = nullptr; // Fall through to return stmt search
      }
    } else {
      // For non-end-of-function nodes, use the statement directly
      Loc = PathDiagnosticLocation(S, BR.getSourceManager(),
                                   N->getLocationContext());
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][REPORT] Using statement location\n";
      }
    }
  }

  if (!S || Loc.asLocation().isInvalid()) {
    // For end-of-function nodes, try to find a ReturnStmt
    const ReturnStmt *RS = findReturnStmt(N);
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][REPORT] findReturnStmt() returned: "
                   << (RS ? "non-null" : "null") << "\n";
    }
    if (RS) {
      Loc = PathDiagnosticLocation(RS, BR.getSourceManager(),
                                   N->getLocationContext());
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][REPORT] Using ReturnStmt location: "
                     << RS->getBeginLoc().printToString(BR.getSourceManager())
                     << "\n";
      }
    } else {
      // Fallback: use declaration end (closing brace)
      Loc = PathDiagnosticLocation::createDeclEnd(N->getLocationContext(),
                                                  BR.getSourceManager());
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][REPORT] Using createDeclEnd location: "
                     << Loc.asLocation().printToString(BR.getSourceManager())
                     << "\n";
      }
    }
  }

  BR.EmitBasicReport(N->getCodeDecl().getASTContext().getTranslationUnitDecl(),
                     ContainingChecker, "Property Violation", "DSL Monitor",
                     diagnosticMsg, Loc);
}

} // namespace

DSLMonitor::DSLMonitor(const CheckerBase *ContainingChecker,
                       std::unique_ptr<PropertyDefinition> Prop)
    : ContainingChecker(ContainingChecker), Property(std::move(Prop)) {

  const LTLFormulaNode *root = Property->Formula.getRootNode();
  std::string infix = buildSpotFormulaString(root);
  if (infix.empty())
    infix = "G 1";

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][SPOT] Original PSL formula: " << infix << "\n";
  }

  spot::parsed_formula pf = spot::parse_infix_psl(infix);
  if (pf.format_errors(std::cerr)) {
    llvm_unreachable("Failed to parse formula");
  }

  // For finite-trace semantics: negate FIRST, then convert to LTLf
  // This ensures the negation is applied to the original formula structure,
  // then finite semantics are added
  spot::formula originalFormula = pf.f;

  // Negate the original formula for violation detection (accepting runs =
  // violations)
  spot::formula negatedFormula = spot::formula::Not(originalFormula);

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][SPOT] Negated PSL formula: "
                 << spot::str_psl(negatedFormula) << "\n";
  }

  // Convert negated formula to LTLf (finite-trace semantics) for Clang Static
  // Analyzer This introduces an "alive" atomic proposition that marks the
  // active portion of the finite trace
  spot::formula negatedLtlfFormula = spot::from_ltlf(negatedFormula, "alive");

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][SPOT] Negated LTLf formula (with 'alive' AP): "
                 << spot::str_psl(negatedLtlfFormula) << "\n";
  }

  // Build Büchi automaton from negated LTLf formula
  spot::translator trans;
  trans.set_type(spot::postprocessor::Buchi);
  trans.set_pref(spot::postprocessor::Deterministic |
                 spot::postprocessor::SBAcc);
  spot::twa_graph_ptr buchiGraph = trans.run(negatedLtlfFormula);

  if (!buchiGraph) {
    llvm_unreachable(
        "Failed to build Büchi automaton from negated LTLf formula");
  }

  // Convert to finite automaton: states with !alive transitions become
  // accepting This gives us proper finite-trace semantics where violations are
  // detected when the trace ends (alive becomes false)
  SpotGraph = spot::to_finite(buchiGraph, "alive");

  if (!SpotGraph) {
    llvm_unreachable("Failed to convert Büchi automaton to finite automaton");
  }

  // First, extract binding variables from the original formula tree
  if (root) {
    std::set<FormulaNodeID> VisitedNodes;
    extractBindingVariables(root, BindingVarForFormulaNode,
                            FormulaNodesForBindingVar, VisitedNodes);
  }

  // Extract atomic propositions from the automaton and build mappings
  // Note: After to_finite(), the "alive" AP may have been removed from the
  // automaton as it's encoded in the state structure. We need to check if it
  // still exists.
  const auto &aps = SpotGraph->ap();
  AtomicPropositionID nextAPID = 0;

  for (const auto &ap : aps) {
    // Get AP name as string
    std::string apName = spot::str_psl(ap);

    // Check if this is the "alive" AP (introduced by from_ltlf)
    if (apName == "alive") {
      // Track the "alive" AP for finite-trace semantics
      auto dict = SpotGraph->get_dict();
      if (!dict) {
        llvm_unreachable("Automaton has no BDD dictionary");
      }

      int bddVar = dict->has_registered_proposition(ap, SpotGraph.get());
      if (bddVar < 0) {
        auto it = dict->var_map.find(ap);
        if (it != dict->var_map.end()) {
          bddVar = it->second;
        } else {
          bddVar = SpotGraph->register_ap(ap);
        }
      }
      AliveAPBDD = bdd_ithvar(bddVar);

      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][DSLMonitor] Found 'alive' AP with BDD var: "
                     << bddVar << "\n";
      }

      // Don't map "alive" to a formula node - it's a framework AP
      continue;
    }

    // Extract NodeID from AP name (format: "ap_N")
    FormulaNodeID nodeID = getNodeIDFromAPName(apName);
    if (nodeID == 0) {
      // Skip APs that don't match our formula node pattern
      continue;
    }

    // Get BDD variable for this AP (should already be registered by translator)
    auto dict = SpotGraph->get_dict();
    if (!dict) {
      llvm_unreachable("Automaton has no BDD dictionary");
    }

    int bddVar = dict->has_registered_proposition(ap, SpotGraph.get());
    if (bddVar < 0) {
      // If not found, try looking it up in var_map directly
      auto it = dict->var_map.find(ap);
      if (it != dict->var_map.end()) {
        bddVar = it->second;
      } else {
        // Fallback: register it (shouldn't happen, but be safe)
        bddVar = SpotGraph->register_ap(ap);
      }
    }
    bdd bddVarBDD = bdd_ithvar(bddVar);

    // Assign sequential APID
    AtomicPropositionID apID = nextAPID++;

    // Build bidirectional mappings
    AtomicPropositionForFormulaNode[nodeID] = apID;
    FormulaNodeForAtomicProposition[apID] = nodeID;
    BDDForAtomicProposition[apID] = bddVarBDD;
  }

  // After to_finite(), the "alive" AP might have been removed.
  // If it's not in the automaton, we need to register it manually for our
  // valuations.
  if (!AliveAPBDD.has_value()) {
    // Try to get it from the original Büchi graph before to_finite()
    // or register it explicitly
    auto dict = SpotGraph->get_dict();
    if (dict) {
      spot::formula aliveAP = spot::formula::ap("alive");
      int bddVar = dict->has_registered_proposition(aliveAP, SpotGraph.get());
      if (bddVar < 0) {
        // Register it explicitly - we'll need it for valuations
        bddVar = SpotGraph->register_ap(aliveAP);
      }
      AliveAPBDD = bdd_ithvar(bddVar);

      if (edslDebugEnabled()) {
        llvm::errs()
            << "[EDSL][DSLMonitor] Registered 'alive' AP with BDD var: "
            << bddVar << "\n";
      }
    }
  }

  // Print debug output if enabled
  if (edslDebugEnabled()) {
    llvm::errs() << "\n[EDSL][DSLMonitor] ========== Monitor Construction "
                    "Complete ==========\n";
    llvm::errs() << "[EDSL][DSLMonitor] Property Name: "
                 << Property->PropertyName << "\n";
    llvm::errs() << "[EDSL][DSLMonitor] Formula String: "
                 << Property->FormulaString << "\n";
    llvm::errs() << "[EDSL][DSLMonitor] Automaton States: "
                 << SpotGraph->num_states() << "\n";
    llvm::errs() << "[EDSL][DSLMonitor] Automaton Edges: "
                 << SpotGraph->num_edges() << "\n";
    llvm::errs() << "[EDSL][DSLMonitor] Initial State: "
                 << SpotGraph->get_init_state_number() << "\n";

    // Print automaton structure (edges)
    llvm::errs() << "[EDSL][DSLMonitor] Automaton Transitions:\n";
    for (unsigned s = 0; s < SpotGraph->num_states(); ++s) {
      llvm::errs() << "  State " << s << " (accepting: "
                   << (SpotGraph->state_is_accepting(s) ? "yes" : "no")
                   << "):\n";
      for (auto &edge : SpotGraph->out(s)) {
        // Try to convert BDD condition to string if possible
        llvm::errs() << "    -> " << edge.dst
                     << " [BDD cond id: " << edge.cond.id() << "]\n";
      }
    }

    // Print accepting states
    llvm::errs() << "[EDSL][DSLMonitor] Accepting States: [";
    bool first = true;
    for (unsigned i = 0; i < SpotGraph->num_states(); ++i) {
      if (SpotGraph->state_is_accepting(i)) {
        if (!first)
          llvm::errs() << ", ";
        llvm::errs() << i;
        first = false;
      }
    }
    llvm::errs() << "]\n";

    // Print Formula Node ID -> Atomic Proposition ID mapping
    llvm::errs()
        << "\n[EDSL][DSLMonitor] Formula Node ID -> Atomic Proposition ID:\n";
    for (const auto &[nodeID, apID] : AtomicPropositionForFormulaNode) {
      llvm::errs() << "  Node " << nodeID << " -> AP " << apID << "\n";
    }

    // Print Atomic Proposition ID -> Formula Node ID mapping
    llvm::errs()
        << "\n[EDSL][DSLMonitor] Atomic Proposition ID -> Formula Node ID:\n";
    for (const auto &[apID, nodeID] : FormulaNodeForAtomicProposition) {
      llvm::errs() << "  AP " << apID << " -> Node " << nodeID << "\n";
    }

    // Print Formula Node ID -> Binding Variable mapping
    llvm::errs()
        << "\n[EDSL][DSLMonitor] Formula Node ID -> Binding Variable:\n";
    for (const auto &[nodeID, bindingVar] : BindingVarForFormulaNode) {
      llvm::errs() << "  Node " << nodeID << " -> ";
      if (bindingVar.has_value()) {
        llvm::errs() << bindingVar.value();
      } else {
        llvm::errs() << "(none)";
      }
      llvm::errs() << "\n";
    }

    // Print Binding Variable -> Formula Node IDs mapping
    llvm::errs()
        << "\n[EDSL][DSLMonitor] Binding Variable -> Formula Node IDs:\n";
    for (const auto &[bindingVar, nodeIDs] : FormulaNodesForBindingVar) {
      llvm::errs() << "  " << bindingVar << " -> [";
      bool firstNode = true;
      for (FormulaNodeID nodeID : nodeIDs) {
        if (!firstNode)
          llvm::errs() << ", ";
        llvm::errs() << nodeID;
        firstNode = false;
      }
      llvm::errs() << "]\n";
    }

    // Print Atomic Proposition ID -> BDD mapping
    llvm::errs()
        << "\n[EDSL][DSLMonitor] Atomic Proposition ID -> BDD Variable:\n";
    for (const auto &[apID, bddVar] : BDDForAtomicProposition) {
      llvm::errs() << "  AP " << apID << " -> BDD var " << bdd_var(bddVar)
                   << "\n";
    }

    llvm::errs() << "[EDSL][DSLMonitor] "
                    "====================================================\n\n";
  }
}

// Event handlers work directly with individual event types
// No more generic CheckerEvent - each handler processes its specific event type
void DSLMonitor::handleEvent(PostCallEvent E) {
  const CallEvent &Call = E.Call;
  CheckerContext &C = E.C;
  ProgramStateRef State = C.getState();
  ASTContext &ASTCtx = C.getASTContext();

  if (edslDebugEnabled()) {
    llvm::errs() << "\n[EDSL][POSTCALL] Processing PostCall event\n";
    if (Call.getOriginExpr()) {
      llvm::errs() << "[EDSL][POSTCALL] Origin expression found\n";
    }
  }

  // Map to store AP valuations: APID -> bool
  std::map<AtomicPropositionID, bool> APValuations;

  // Step 1: Enumerate and evaluate all APs
  for (const auto &[apID, nodeID] : FormulaNodeForAtomicProposition) {
    // Get the formula node to check if it's an AtomicNode
    const LTLFormulaNode *node = Property->Formula.getNodeByID(nodeID);
    if (!node || node->Type != LTLNodeType::Atomic) {
      continue; // Skip non-atomic nodes
    }

    const AtomicNode *Atomic = static_cast<const AtomicNode *>(node);

    // Check if this AP should be evaluated for PostCall
    bool shouldEvaluate = false;
    if (!Atomic->Binding.has_value()) {
      // No binding - always evaluate
      shouldEvaluate = true;
    } else {
      // Has binding - only evaluate if ReturnValue or ReturnValueNonNull
      BindingType bindingType = Atomic->Binding->Type;
      if (bindingType == BindingType::ReturnValue ||
          bindingType == BindingType::ReturnValueNonNull) {
        shouldEvaluate = true;
      }
    }

    if (!shouldEvaluate) {
      APValuations[apID] = false;
      continue;
    }

    // Evaluate AP using helper function
    auto [apValue, needsBindingHandling] =
        evaluateAP(Atomic, apID, nodeID, State, Call, ASTCtx, "POSTCALL");

    APValuations[apID] = apValue;

    // Handle binding if needed (for PostCall, this is return value handling)
    if (needsBindingHandling && Atomic->Binding.has_value()) {
      SVal RetVal = Call.getReturnValue();
      SymbolRef RetSym = RetVal.getAsSymbol();

      if (!RetSym) {
        // Try to get symbol from the origin expression value
        const Expr *Origin = Call.getOriginExpr();
        if (Origin) {
          RetSym = C.getSVal(Origin).getAsSymbol();
        }
      }

      if (RetSym) {
        BindingType bindingType = Atomic->Binding->Type;
        const BindingVarID &bindingVar = Atomic->Binding->BindingName;

        if (bindingType == BindingType::ReturnValueNonNull) {
          // Split state for non-null
          if (RetVal.getAs<Loc>()) {
            auto LocVal = RetVal.getAs<Loc>();
            auto Pair = State->assume(*LocVal);
            ProgramStateRef StateNotNull = Pair.first; // non-null branch
            ProgramStateRef StateNull = Pair.second;   // null branch

            // Handle null branch - don't track binding, add transition and
            // return
            if (StateNull) {
              C.addTransition(StateNull);
            }

            // Continue with non-null branch
            if (StateNotNull) {
              State = StateNotNull;
              // Track binding var -> symbol in GDM
              State = setBindingVarForSymbol(State, RetSym, bindingVar);
              if (edslDebugEnabled()) {
                llvm::errs()
                    << "[EDSL][POSTCALL] Split state: null branch added, "
                    << "tracking binding var '" << bindingVar
                    << "' -> symbol on non-null branch\n";
              }
            } else {
              // Non-null branch is infeasible
              return;
            }
          }
        } else {
          // ReturnValue (without non-null) - just track the binding
          State = setBindingVarForSymbol(State, RetSym, bindingVar);
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][POSTCALL] Tracking binding var '"
                         << bindingVar << "' -> symbol\n";
          }
        }
      }
    }
  }

  // Step 2: Build BDD valuation from AP evaluations
  // For finite-trace semantics: set "alive" = true during execution
  bdd valuation = buildBDDValuation(APValuations, BDDForAtomicProposition, true,
                                    AliveAPBDD, "POSTCALL");

  // Step 3: Get current automaton state
  // For PostCall, track per-symbol. Find the symbol we just processed.
  unsigned currentState = SpotGraph->get_init_state_number();
  SymbolRef trackedSym = nullptr;

  // Get the return value symbol that we may have just set bindings for
  SVal RetVal = Call.getReturnValue();
  trackedSym = RetVal.getAsSymbol();

  // If we didn't get a symbol from return value, try to find any symbol with a
  // binding
  if (!trackedSym) {
    const Expr *Origin = Call.getOriginExpr();
    if (Origin) {
      trackedSym = C.getSVal(Origin).getAsSymbol();
    }
  }

  // If we have a symbol, check if it already has an automaton state
  if (trackedSym) {
    const AutomatonStateID *storedState =
        getAutomatonStateForSymbol(State, trackedSym);
    if (storedState) {
      currentState = *storedState;
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][POSTCALL] Found existing automaton state "
                     << currentState << " for symbol\n";
      }
    } else {
      // New symbol - start from initial state
      currentState = SpotGraph->get_init_state_number();
      if (edslDebugEnabled()) {
        llvm::errs()
            << "[EDSL][POSTCALL] New symbol, starting from initial state "
            << currentState << "\n";
      }
    }
  }

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][POSTCALL] Current automaton state: " << currentState
                 << "\n";
  }

  // Step 4: Step automaton based on BDD valuation
  auto [nextState, foundTransition, violatingEdgeCond] =
      stepAutomaton(currentState, valuation, SpotGraph, "POSTCALL");

  // Step 5: Handle violation detection and state updates
  bool isAccepting = SpotGraph->state_is_accepting(nextState);

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][POSTCALL] Transitioned to state " << nextState
                 << " (accepting: " << (isAccepting ? "yes" : "no") << ")\n";
  }

  // Report immediate violations (e.g., double-free in state 3)
  // Defer liveness violations (e.g., leak in state 1) to EndAnalysis
  // State 1 = leak (needs end-of-trace check)
  // State 3 = double-free (immediate safety violation)
  if (isAccepting && nextState == 3) {
    // Immediate violation: double-free detected
    ExplodedNode *ViolationNode = C.generateNonFatalErrorNode(State);
    if (ViolationNode) {
      reportViolation(nextState, violatingEdgeCond, foundTransition,
                      BDDForAtomicProposition, FormulaNodeForAtomicProposition,
                      Property->Formula, ViolationNode, C.getBugReporter(),
                      ContainingChecker);
      return; // Don't continue after reporting violation
    }
  } else if (isAccepting && edslDebugEnabled()) {
    // State 1 (leak) - defer to EndAnalysis
    llvm::errs()
        << "[EDSL][POSTCALL] Note: Accepting state " << nextState
        << " reached (likely leak), violation will be reported at EndAnalysis "
           "(alive=false)\n";
  }

  // Update GDM and add transition (we always do this during execution)
  if (trackedSym) {
    State = setAutomatonStateForSymbol(State, trackedSym, nextState);
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][POSTCALL] Updated automaton state to "
                   << nextState << " for symbol\n";
    }
  }

  // Add transition to exploded graph
  C.addTransition(State);

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][POSTCALL] Added transition to state " << nextState
                 << "\n";
    // Print GDM state and internal maps for verification
    if (trackedSym) {
      const AutomatonStateID *storedState =
          getAutomatonStateForSymbol(State, trackedSym);
      if (storedState) {
        llvm::errs() << "[EDSL][POSTCALL] GDM automaton state: " << *storedState
                     << "\n";
      } else {
        llvm::errs() << "[EDSL][POSTCALL] GDM automaton state: (not set)\n";
      }
      const BindingVarID *storedBinding =
          getBindingVarForSymbol(State, trackedSym);
      if (storedBinding) {
        llvm::errs() << "[EDSL][POSTCALL] GDM binding var: " << *storedBinding
                     << "\n";
        // Verify internal map consistency
        auto it = FormulaNodesForBindingVar.find(*storedBinding);
        if (it != FormulaNodesForBindingVar.end()) {
          llvm::errs() << "[EDSL][POSTCALL] Internal map: binding var '"
                       << *storedBinding << "' -> nodes: [";
          bool first = true;
          for (FormulaNodeID nid : it->second) {
            if (!first)
              llvm::errs() << ", ";
            llvm::errs() << nid;
            first = false;
          }
          llvm::errs() << "]\n";
        }
      } else {
        llvm::errs() << "[EDSL][POSTCALL] GDM binding var: (not set)\n";
      }
    }
    // Print AP valuations for verification
    llvm::errs() << "[EDSL][POSTCALL] AP valuations: ";
    bool first = true;
    for (const auto &[apID, value] : APValuations) {
      if (!first)
        llvm::errs() << ", ";
      llvm::errs() << "AP" << apID << "=" << (value ? "T" : "F");
      first = false;
    }
    llvm::errs() << "\n";
    llvm::errs() << "[EDSL][POSTCALL] Processing complete\n\n";
  }
}

void DSLMonitor::handleEvent(PreCallEvent E) {
  const CallEvent &Call = E.Call;
  CheckerContext &C = E.C;
  ProgramStateRef State = C.getState();
  ASTContext &ASTCtx = C.getASTContext();

  if (edslDebugEnabled()) {
    llvm::errs() << "\n[EDSL][PRECALL] Processing PreCall event\n";
    if (Call.getOriginExpr()) {
      llvm::errs() << "[EDSL][PRECALL] Origin expression found\n";
    }
  }

  // Map to store AP valuations: APID -> bool
  std::map<AtomicPropositionID, bool> APValuations;

  // Track symbols that were bound during AP evaluation (for automaton state
  // tracking)
  std::set<SymbolRef> BoundSymbols;
  std::map<SymbolRef, int> SymbolToParameterIndex;

  // Step 1: Enumerate and evaluate all APs
  for (const auto &[apID, nodeID] : FormulaNodeForAtomicProposition) {
    // Get the formula node to check if it's an AtomicNode
    const LTLFormulaNode *node = Property->Formula.getNodeByID(nodeID);
    if (!node || node->Type != LTLNodeType::Atomic) {
      continue; // Skip non-atomic nodes
    }

    const AtomicNode *Atomic = static_cast<const AtomicNode *>(node);

    // Check if this AP should be evaluated for PreCall
    bool shouldEvaluate = false;
    if (!Atomic->Binding.has_value()) {
      // No binding - always evaluate
      shouldEvaluate = true;
    } else {
      // Has binding - only evaluate if FirstParameter or FirstParameterNonNull
      BindingType bindingType = Atomic->Binding->Type;
      if (bindingType == BindingType::FirstParameter ||
          bindingType == BindingType::FirstParameterNonNull ||
          bindingType == BindingType::NthParameter ||
          bindingType == BindingType::NthParameterNonNull) {
        shouldEvaluate = true;
      }
    }

    if (!shouldEvaluate) {
      APValuations[apID] = false;
      continue;
    }

    // Evaluate AP using helper function
    auto [apValue, needsBindingHandling] =
        evaluateAP(Atomic, apID, nodeID, State, Call, ASTCtx, "PRECALL");

    APValuations[apID] = apValue;

    // Handle binding if needed (for PreCall, this is parameter handling)
    if (needsBindingHandling && Atomic->Binding.has_value()) {
      // Determine parameter index based on binding type
      int paramIndex = 0;
      if (Atomic->Binding->Type == BindingType::NthParameter ||
          Atomic->Binding->Type == BindingType::NthParameterNonNull) {
        paramIndex = Atomic->Binding->ParameterIndex;
      } else if (Atomic->Binding->Type == BindingType::FirstParameter ||
                 Atomic->Binding->Type == BindingType::FirstParameterNonNull) {
        paramIndex = 0;
      }

      if (static_cast<int>(Call.getNumArgs()) <= paramIndex) {
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][PRECALL] Parameter index " << paramIndex
                       << " not available (only " << Call.getNumArgs()
                       << " arguments)\n";
        }
        continue;
      }

      SVal ArgVal = Call.getArgSVal(paramIndex);
      SymbolRef ArgSym = ArgVal.getAsSymbol();

      if (!ArgSym) {
        // Try to get symbol from the argument expression
        const Expr *ArgExpr = Call.getArgExpr(paramIndex);
        if (ArgExpr) {
          ArgSym = C.getSVal(ArgExpr).getAsSymbol();
        }
      }

      if (ArgSym) {
        BindingType bindingType = Atomic->Binding->Type;
        const BindingVarID &bindingVar = Atomic->Binding->BindingName;

        // Track this symbol for automaton state lookup later
        BoundSymbols.insert(ArgSym);
        SymbolToParameterIndex[ArgSym] = paramIndex;

        if (bindingType == BindingType::FirstParameterNonNull ||
            bindingType == BindingType::NthParameterNonNull) {
          // Split state for non-null
          if (ArgVal.getAs<Loc>()) {
            auto LocVal = ArgVal.getAs<Loc>();
            auto Pair = State->assume(*LocVal);
            ProgramStateRef StateNotNull = Pair.first; // non-null branch
            ProgramStateRef StateNull = Pair.second;   // null branch

            // Handle null branch - don't track binding, add transition and
            // return
            if (StateNull) {
              C.addTransition(StateNull);
            }

            // Continue with non-null branch
            if (StateNotNull) {
              State = StateNotNull;
              // Track binding var -> symbol in GDM
              State = setBindingVarForSymbol(State, ArgSym, bindingVar);
              if (edslDebugEnabled()) {
                llvm::errs()
                    << "[EDSL][PRECALL] Split state: null branch added, "
                    << "tracking binding var '" << bindingVar
                    << "' -> symbol on non-null branch (param index "
                    << paramIndex << ")\n";
              }
            } else {
              // Non-null branch is infeasible
              return;
            }
          }
        } else {
          // FirstParameter or NthParameter (without non-null) - just track the
          // binding
          State = setBindingVarForSymbol(State, ArgSym, bindingVar);
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][PRECALL] Tracking binding var '"
                         << bindingVar << "' -> symbol (param index "
                         << paramIndex << ")\n";
          }
        }
      }
    }
  }

  // Step 2: Build BDD valuation from AP evaluations
  // For finite-trace semantics: set "alive" = true during execution
  bdd valuation = buildBDDValuation(APValuations, BDDForAtomicProposition, true,
                                    AliveAPBDD, "PRECALL");

  // Step 3: Get current automaton state
  // For PreCall, track per-symbol. Find the symbol(s) we just processed.
  unsigned currentState = SpotGraph->get_init_state_number();
  SymbolRef trackedSym = nullptr;

  // Use the first bound symbol for automaton state tracking
  // If multiple symbols were bound, they should all reference the same
  // binding variable in the formula, so tracking one is sufficient
  if (!BoundSymbols.empty()) {
    trackedSym = *BoundSymbols.begin();
    const AutomatonStateID *existingState =
        getAutomatonStateForSymbol(State, trackedSym);
    if (existingState) {
      currentState = *existingState;
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][PRECALL] Current automaton state: "
                     << currentState << " for symbol (from param index "
                     << SymbolToParameterIndex[trackedSym] << ")\n";
      }
    } else {
      if (edslDebugEnabled()) {
        llvm::errs()
            << "[EDSL][PRECALL] New symbol, starting from initial state "
            << currentState << " (from param index "
            << SymbolToParameterIndex[trackedSym] << ")\n";
      }
    }
  } else {
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][PRECALL] No symbol found, using initial state "
                   << currentState << "\n";
    }
  }

  // Step 4: Step the automaton to the next state based on BDD valuation
  auto [nextState, foundTransition, violatingEdgeCond] =
      stepAutomaton(currentState, valuation, SpotGraph, "PRECALL");

  // Step 5: Handle violation detection
  bool isAccepting = SpotGraph->state_is_accepting(nextState);

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][PRECALL] Transitioned to state " << nextState
                 << " (accepting: " << (isAccepting ? "yes" : "no") << ")\n";
  }

  // Report immediate violations (e.g., double-free in state 3)
  // Defer liveness violations (e.g., leak in state 1) to EndAnalysis
  if (isAccepting && nextState == 3) {
    // Immediate violation: double-free detected
    ExplodedNode *ViolationNode = C.generateNonFatalErrorNode(State);
    if (ViolationNode) {
      reportViolation(nextState, violatingEdgeCond, foundTransition,
                      BDDForAtomicProposition, FormulaNodeForAtomicProposition,
                      Property->Formula, ViolationNode, C.getBugReporter(),
                      ContainingChecker);
      return; // Don't continue after reporting violation
    }
  } else if (isAccepting && edslDebugEnabled()) {
    // State 1 (leak) - defer to EndAnalysis
    llvm::errs()
        << "[EDSL][PRECALL] Note: Accepting state " << nextState
        << " reached (likely leak), violation will be reported at EndAnalysis "
           "(alive=false)\n";
  }

  // Step 6: Update GDM and add transition to exploded graph
  if (trackedSym) {
    State = setAutomatonStateForSymbol(State, trackedSym, nextState);
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][PRECALL] Updated automaton state to " << nextState
                   << " for symbol\n";
    }
  }

  C.addTransition(State);

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][PRECALL] Added transition to state " << nextState
                 << "\n";
    if (trackedSym) {
      const AutomatonStateID *gdmState =
          getAutomatonStateForSymbol(State, trackedSym);
      if (gdmState) {
        llvm::errs() << "[EDSL][PRECALL] GDM automaton state: " << *gdmState
                     << "\n";
      }
      const BindingVarID *gdmVar = getBindingVarForSymbol(State, trackedSym);
      if (gdmVar) {
        llvm::errs() << "[EDSL][PRECALL] GDM binding var: " << *gdmVar << "\n";
      }
    }
    llvm::errs() << "[EDSL][PRECALL] AP valuations: ";
    for (const auto &[apID, value] : APValuations) {
      llvm::errs() << "AP" << apID << "=" << (value ? "T" : "F") << " ";
    }
    llvm::errs() << "\n";
    llvm::errs() << "[EDSL][PRECALL] Processing complete\n";
  }
}

void DSLMonitor::handleEvent(DeadSymbolsEvent E) {
  // TODO: Implement direct handling without CheckerEvent
  (void)E;
}

void DSLMonitor::handleEvent(EndAnalysisEvent E) {
  ExplodedGraph &G = E.G;
  BugReporter &BR = E.BR;

  if (edslDebugEnabled()) {
    llvm::errs()
        << "\n[EDSL][ENDANALYSIS] Checking for violations at end of analysis\n";
  }

  // Collect all unique end states (to avoid duplicate checking)
  // Use raw pointers for deduplication (matching codebase pattern)
  llvm::DenseSet<const ProgramState *> ProcessedStates;

  // Iterate through all end nodes (nodes with no successors)
  using GraphTraits = llvm::GraphTraits<ExplodedGraph *>;
  for (auto I = GraphTraits::nodes_begin(&G), End = GraphTraits::nodes_end(&G);
       I != End; ++I) {
    ExplodedNode *N = *I;
    if (!N || N->succ_size() != 0) // Only process end nodes
      continue;

    ProgramStateRef State = N->getState();
    if (!State)
      continue;

    // Skip if we've already processed this state
    // Use raw pointer for hashing/comparison
    if (!ProcessedStates.insert(State.get()).second)
      continue;

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][ENDANALYSIS] Checking end node " << N->getID()
                   << "\n";
    }

    // Get the AutomatonStateForSymbol map from GDM
    auto AutomatonStateMap = State->get<AutomatonStateForSymbol>();

    // Iterate through all tracked symbols in this state
    for (auto It = AutomatonStateMap.begin(), End = AutomatonStateMap.end();
         It != End; ++It) {
      AutomatonStateID currentState = It.getData();

      if (edslDebugEnabled()) {
        llvm::errs()
            << "[EDSL][ENDANALYSIS] Checking symbol with automaton state "
            << currentState << "\n";
      }

      // Build BDD valuation for end of trace: alive=false, all APs=false
      std::map<AtomicPropositionID, bool> endOfTraceValuations;
      for (const auto &[apID, nodeID] : FormulaNodeForAtomicProposition) {
        endOfTraceValuations[apID] = false; // All APs false at end
      }
      bdd valuation =
          buildBDDValuation(endOfTraceValuations, BDDForAtomicProposition,
                            false, AliveAPBDD, "ENDANALYSIS");

      // Step automaton with end-of-trace valuation
      auto [nextState, foundTransition, violatingEdgeCond] =
          stepAutomaton(currentState, valuation, SpotGraph, "ENDANALYSIS");

      // Check if the resulting state is accepting (violation)
      bool isViolation = SpotGraph->state_is_accepting(nextState);

      if (isViolation) {
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][ENDANALYSIS]   VIOLATION DETECTED! State "
                       << nextState << " is accepting\n";
        }

        // Report violation using helper (extracts diagnostics from formula)
        reportViolation(nextState, violatingEdgeCond, foundTransition,
                        BDDForAtomicProposition,
                        FormulaNodeForAtomicProposition, Property->Formula, N,
                        BR, ContainingChecker);
      } else if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][ENDANALYSIS]   No violation (state "
                     << nextState << " is non-accepting)\n";
      }
    }
  }

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][ENDANALYSIS] End of analysis check complete\n\n";
  }
}
