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
SpotMonitor::SpotMonitor(spot::twa_graph_ptr M, APRegistry R,
                         const LTLFormulaBuilder &B)
    : Monitor(std::move(M)), Registry(std::move(R)), Builder(B) {
  // Let the automaton own AP registrations so the dict tracks associations
  if (Monitor) {
    for (const auto &kv : Registry.getEvaluators()) {
      const std::string &ap = kv.first;
      int var = Monitor->register_ap(ap);
      ApVarIds[ap] = var;
    }
  }
}


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
          return !IsNull.isConstrainedTrue();
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

std::set<int> SpotMonitor::step(const GenericEvent &E, CheckerContext &C) {
  std::set<int> violated;
  if (!Monitor)
    return violated;

  // Compute valuation of APs for this event
  std::set<std::string> trueAPs;
  for (const auto &kv : Registry.getEvaluators()) {
    const std::string &ap = kv.first;
    const auto &eval = kv.second;
    if (eval(E, C))
      trueAPs.insert(ap);
  }
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][SPOT] step: trueAPs={";
    bool first = true;
    for (const auto &a : trueAPs) { if (!first) llvm::errs() << ','; first=false; llvm::errs() << a; }
    llvm::errs() << "}\n";
  }

  // Build valuation cube by assigning all known AP variables.
  bdd valuation = bddtrue;
  for (const auto &kv : Registry.getEvaluators()) {
    const std::string &ap = kv.first;
    auto it = ApVarIds.find(ap);
    if (it == ApVarIds.end()) continue;
    int var = it->second;
    valuation = bdd_and(valuation, trueAPs.count(ap) ? bdd_ithvar(var)
                                                     : bdd_nithvar(var));
  }

  // Determine next state by scanning outgoing edges and selecting the
  // first whose condition evaluates to true under current AP valuation.
  unsigned ns = Monitor->num_states();
  if (CurrentState >= (int)ns)
    CurrentState = 0;
  int nextState = CurrentState;
  bool matched = false;
  for (auto &t : Monitor->out(CurrentState)) {
    // Check satisfiability of transition condition under current assignment.
    bdd sat = bdd_restrict(t.cond, valuation);
    if (sat != bddfalse) {
      nextState = (int)t.dst;
      matched = true;
      break;
    }
  }

  if (matched) {
    CurrentState = nextState;
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][SPOT] transition to state " << CurrentState << "\n";
    }
    return violated; // ok
  }

  // No transition satisfied: approximate violation, attribute to true APs
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][SPOT] no transition matched; reporting violation\n";
  }
  for (const auto &p : Registry.getMapping()) {
    int nodeId = p.first;
    const std::string &ap = p.second;
    if (trueAPs.count(ap))
      violated.insert(nodeId);
  }
  return violated;
}

std::unique_ptr<DSLMonitor> DSLMonitor::create(
    std::unique_ptr<PropertyDefinition> Property, const CheckerBase *O) {
  auto Runtime = std::make_unique<dsl::MonitorAutomaton>(std::move(Property), O);
  auto fb = Runtime->getFormulaBuilder();
  auto res = dsl::buildSpotMonitorFromDSL(fb);
  std::unique_ptr<dsl::SpotMonitor> S;
  if (res.Monitor)
    S = std::make_unique<dsl::SpotMonitor>(std::move(res.Monitor), std::move(res.Registry), fb);
  return std::make_unique<DSLMonitor>(std::move(Runtime), std::move(S), O);
}

void DSLMonitor::handleEvent(const GenericEvent &event, CheckerContext &C) {
  // Framework modeling
  Runtime->handleEvent(event, C);
  // SPOT temporal step + report
  if (Spot) {
    auto violated = Spot->step(event, C);
    if (!violated.empty()) {
      std::string msg = Spot->selectDiagnosticForViolation(violated);
      if (msg.empty()) msg = "temporal property violated";
      ExplodedNode *ErrorNode = C.generateErrorNode(C.getState());
      if (ErrorNode) {
        static const BugType GenericBT{Owner, "temporal_violation", "EmbeddedDSLMonitor"};
        auto R = std::make_unique<PathSensitiveBugReport>(GenericBT, msg, ErrorNode);
        if (event.Symbol)
          R->markInteresting(event.Symbol);
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

 


