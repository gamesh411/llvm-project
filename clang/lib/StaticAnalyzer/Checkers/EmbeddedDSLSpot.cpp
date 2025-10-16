#include "EmbeddedDSLSpot.h"

// Minimal SPOT includes; concrete usage will be filled incrementally
#include <spot/tl/parse.hh>
#include <spot/tl/print.hh>
#include <spot/twaalgos/translate.hh>
#include <spot/twa/twagraph.hh>
#include <spot/twa/bdddict.hh>

using namespace clang;
using namespace ento;
using namespace dsl;

namespace {

static std::string makeAPName(int nodeId) { return "ap_" + std::to_string(nodeId); }

// Recursively build a SPOT-compatible infix PSL string from our DSL AST,
// while registering atomic propositions and their evaluators into the registry.
static std::string buildSpotFormulaString(const LTLFormulaNode *node,
                                          APRegistry &reg) {
  if (!node)
    return "1"; // true

  switch (node->Type) {
  case LTLNodeType::Atomic: {
    const int id = node->NodeID;
    const std::string ap = makeAPName(id);
    // Capture values needed for evaluation
    const std::string fn = node->FunctionName;
    const std::string sym = node->Binding.SymbolName;
    const BindingType bt = node->Binding.Type;

    APEvaluator eval = [fn, sym, bt](const GenericEvent &E, CheckerContext &C) -> bool {
      (void)C;
      // Variable-only AP: true if the current event references the same symbol
      if (fn.empty()) {
        return (!sym.empty() && E.SymbolName == sym);
      }
      // Function AP: true if this event is for that function on the bound symbol
      if (E.FunctionName != fn)
        return false;
      if (sym.empty())
        return true;
      return E.SymbolName == sym;
    };
    reg.registerAP(id, ap, std::move(eval));
    return ap;
  }
  case LTLNodeType::And:
    return std::string("(") + buildSpotFormulaString(node->Children[0].get(), reg) +
           " & " + buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Or:
    return std::string("(") + buildSpotFormulaString(node->Children[0].get(), reg) +
           " | " + buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Implies:
    return std::string("(") + buildSpotFormulaString(node->Children[0].get(), reg) +
           " -> " + buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Not:
    return std::string("!(") + buildSpotFormulaString(node->Children[0].get(), reg) + ")";
  case LTLNodeType::Globally:
    return std::string("G(") + buildSpotFormulaString(node->Children[0].get(), reg) + ")";
  case LTLNodeType::Eventually:
    return std::string("F(") + buildSpotFormulaString(node->Children[0].get(), reg) + ")";
  case LTLNodeType::Next:
    return std::string("X(") + buildSpotFormulaString(node->Children[0].get(), reg) + ")";
  case LTLNodeType::Until:
    return std::string("(") + buildSpotFormulaString(node->Children[0].get(), reg) +
           " U " + buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Release:
    return std::string("(") + buildSpotFormulaString(node->Children[0].get(), reg) +
           " R " + buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  }
  return "1";
}

}

SpotBuildResult dsl::buildSpotMonitorFromDSL(const LTLFormulaBuilder &Builder) {
  SpotBuildResult R;

  // Translate DSL → infix PSL and register AP evaluators.
  const LTLFormulaNode *root = Builder.getRootNode();
  std::string infix = buildSpotFormulaString(root, R.Registry);
  if (infix.empty()) infix = "G 1";

  spot::parsed_formula pf = spot::parse_infix_psl(infix);
  if (pf.format_errors(std::cerr)) {
    return R;
  }
  spot::translator trans;
  trans.set_type(spot::postprocessor::Monitor);
  trans.set_pref(spot::postprocessor::Deterministic);
  R.Monitor = trans.run(pf.f);
  return R;
}

std::set<int> SpotMonitor::step(const GenericEvent &E, CheckerContext &C) {
  // Temporarily disable stepping to isolate checker crashes unrelated to SPOT.
  (void)E;
  (void)C;
  return {};
}

 


