#include "EmbeddedDSLSpot.h"

// Minimal SPOT includes; concrete usage will be filled incrementally
#include <spot/tl/parse.hh>
#include <spot/tl/print.hh>
#include <spot/twaalgos/translate.hh>
#include <spot/twa/twagraph.hh>
#include <spot/twa/bdddict.hh>
#include <spot/twa/bddprint.hh>
#include <spot/tl/formula.hh>

using namespace clang;
using namespace ento;
using namespace dsl;
// removed SpotMonitor in favor of unified DSLMonitor


namespace {
// Tiny boolean evaluator for formulas produced from BDDs using only !, &, |, (),
// and atomic proposition names like "ap_1".
struct BoolParser {
  const std::string &S;
  size_t I = 0;
  const std::set<std::string> &TrueAPs;
  BoolParser(const std::string &s, const std::set<std::string> &aps)
      : S(s), TrueAPs(aps) {}

  void skipWS() {
    while (I < S.size() && isspace(static_cast<unsigned char>(S[I]))) ++I;
  }

  bool parseExpr() {
    bool v = parseTerm();
    skipWS();
    while (I < S.size()) {
      if (S[I] == '|') {
        ++I;
        bool rhs = parseTerm();
        v = v || rhs;
        skipWS();
      } else {
        break;
      }
    }
    return v;
  }

  bool parseTerm() {
    bool v = parseFactor();
    skipWS();
    while (I < S.size()) {
      if (S[I] == '&') {
        ++I;
        bool rhs = parseFactor();
        v = v && rhs;
        skipWS();
      } else {
        break;
      }
    }
    return v;
  }

  bool parseFactor() {
    skipWS();
    if (I >= S.size()) return false;
    if (S[I] == '!') {
      ++I;
      return !parseFactor();
    }
    if (S[I] == '(') {
      ++I;
      bool v = parseExpr();
      skipWS();
      if (I < S.size() && S[I] == ')') ++I;
      return v;
    }
    // Parse identifier or constants 1/0
    if (S[I] == '1') { ++I; return true; }
    if (S[I] == '0') { ++I; return false; }
    size_t start = I;
    while (I < S.size() && (isalnum(static_cast<unsigned char>(S[I])) || S[I] == '_' || S[I] == '.')) ++I;
    std::string tok = S.substr(start, I - start);
    if (tok.empty()) return false;
    return TrueAPs.count(tok) != 0;
  }
};


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
      // Predicate: __isnonnull(x)
      if (fn == "__isnonnull") {
        if (E.Symbol && E.SymbolName == sym) {
          ProgramStateRef S = C.getState();
          ConditionTruthVal IsNull = C.getConstraintManager().isNull(S, E.Symbol);
          // Strict: true only when provably non-null on this path
          return IsNull.isConstrainedFalse();
        }
        return false;
      }
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

  // Internally append an End AP evaluator so the monitor can observe function-end.
  // The End AP is true only on EndFunction events. It is not referenced by the DSL formula yet.
  {
    const std::string apEnd = "ap_END";
    APEvaluator endEval = [](const GenericEvent &E, CheckerContext &C) -> bool {
      (void)C;
      return E.Type == EventType::EndFunction;
    };
    // Use nodeId -1 for synthetic AP; it won't map to any DSL node.
    R.Registry.registerAP(-1, apEnd, std::move(endEval));
  }

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

std::unique_ptr<DSLMonitor> DSLMonitor::create(
    std::unique_ptr<PropertyDefinition> Property, const CheckerBase *O) {
  auto Runtime = std::make_unique<dsl::MonitorAutomaton>(std::move(Property), O);
  auto fb = Runtime->getFormulaBuilder();
  auto res = dsl::buildSpotMonitorFromDSL(fb);
  return std::make_unique<DSLMonitor>(std::move(Runtime), std::move(res.Monitor), std::move(res.Registry), O);
}

void DSLMonitor::handleEvent(const GenericEvent &event, CheckerContext &C) {
  // Framework modeling
  Runtime->handleEvent(event, C);
  // SPOT temporal step + report
  if (SpotGraph) {
    // Pre-register APs into the SpotGraph's dict (once)
    if (ApVarIds.empty()) {
      for (const auto &kv : Registry.getEvaluators()) {
        const std::string &ap = kv.first;
        int var = SpotGraph->register_ap(ap);
        ApVarIds[ap] = var;
      }
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] APs registered: ";
        bool first=true; for (auto &kv : ApVarIds) { if (!first) llvm::errs() << ", "; first=false; llvm::errs() << kv.first << "->" << kv.second; }
        llvm::errs() << "\n";
      }
    }
    // Debug: print event
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][SPOT] event: type=" << (int)event.Type
                   << ", fn=" << event.FunctionName
                   << ", sym=" << event.SymbolName << "\n";
    }
    // Evaluate APs
    std::set<std::string> trueAPs;
    for (const auto &kv : Registry.getEvaluators()) {
      const std::string &ap = kv.first;
      const auto &eval = kv.second;
      if (eval(event, C)) trueAPs.insert(ap);
    }
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][SPOT] AP valuation: ";
      for (const auto &kv : Registry.getEvaluators()) {
        const std::string &ap = kv.first;
        bool val = trueAPs.count(ap);
        // Try to map AP back to DSL node and function
        int nodeId = -1; for (const auto &m : Registry.getMapping()) if (m.second == ap) { nodeId = m.first; break; }
        const LTLFormulaNode *node = Runtime->getFormulaBuilder().getNodeByID(nodeId);
        std::string who = node ? (node->FunctionName.empty() ? node->Binding.SymbolName : node->FunctionName + "(" + node->Binding.SymbolName + ")") : std::string("<synthetic>");
        llvm::errs() << ap << "=" << (val?"T":"F") << "[" << who << "] ";
      }
      llvm::errs() << "\n";
    }

    // Build valuation cube
    bdd valuation = bddtrue;
    for (const auto &kv : Registry.getEvaluators()) {
      const std::string &ap = kv.first;
      int var = ApVarIds[ap];
      valuation = bdd_and(valuation, trueAPs.count(ap) ? bdd_ithvar(var)
                                                       : bdd_nithvar(var));
    }

    // Step through transitions
    unsigned ns = SpotGraph->num_states();
    if (CurrentState >= (int)ns) CurrentState = 0;
    int nextState = CurrentState; bool matched = false;
    for (auto &t : SpotGraph->out(CurrentState)) {
      bdd sat = bdd_restrict(t.cond, valuation);
      if (sat != bddfalse) { nextState = (int)t.dst; matched = true; break; }
    }
    if (matched) {
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] state " << CurrentState << " -> " << nextState << "\n";
      }
      CurrentState = nextState;
    } else {
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] no transition satisfied from state " << CurrentState << "; temporal violation" << "\n";
      }
      // Emit a temporal violation diagnostic
      ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
      if (ErrorNode) {
        static const BugType BT{Owner, "temporal_violation", "EmbeddedDSLMonitor"};
        std::string msg = "temporal property violated (no transition satisfied)";
        auto R = std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
        C.emitReport(std::move(R));
      }
    }
  }
}

void DSLMonitor::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  (void)Eng;
  for (auto I = llvm::GraphTraits<ExplodedGraph *>::nodes_begin(&G),
            E = llvm::GraphTraits<ExplodedGraph *>::nodes_end(&G);
       I != E; ++I) {
    const ExplodedNode *N = *I;
    ProgramStateRef S = N ? N->getState() : nullptr;
    if (!S)
      continue;
    for (auto Sym : S->get<::PendingLeakSet>()) {
      static const BugType BT{Owner, "temporal_violation_end_analysis", "EmbeddedDSLMonitor"};
      ExplodedNode *EN = const_cast<ExplodedNode *>(N);
      std::string internal = "sym_" + std::to_string(Sym->getSymbolID());
      std::string Msg =
          "resource not destroyed before analysis end (violates exactly-once)";
      Msg += " (internal symbol: " + internal + ")";
      Msg += " [reported at EndAnalysis; not all program paths may have been fully explored]";
      auto R = std::make_unique<PathSensitiveBugReport>(BT, Msg, EN);
      R->markInteresting(Sym);
      BR.emitReport(std::move(R));
    }
  }
}

 


