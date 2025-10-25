#include "EmbeddedDSLSpot.h"

// Minimal SPOT includes; concrete usage will be filled incrementally
#include <spot/tl/formula.hh>
#include <spot/tl/parse.hh>
#include <spot/tl/print.hh>
#include <spot/twa/bdddict.hh>
#include <spot/twa/bddprint.hh>
#include <spot/twa/twagraph.hh>
#include <spot/twaalgos/translate.hh>

using namespace clang;
using namespace ento;
using namespace dsl;
// removed SpotMonitor in favor of unified DSLMonitor

namespace {
// Tiny boolean evaluator for formulas produced from BDDs using only !, &, |,
// (), and atomic proposition names like "ap_1".
struct BoolParser {
  const std::string &S;
  size_t I = 0;
  const std::set<std::string> &TrueAPs;
  BoolParser(const std::string &s, const std::set<std::string> &aps)
      : S(s), TrueAPs(aps) {}

  void skipWS() {
    while (I < S.size() && isspace(static_cast<unsigned char>(S[I])))
      ++I;
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
    if (I >= S.size())
      return false;
    if (S[I] == '!') {
      ++I;
      return !parseFactor();
    }
    if (S[I] == '(') {
      ++I;
      bool v = parseExpr();
      skipWS();
      if (I < S.size() && S[I] == ')')
        ++I;
      return v;
    }
    // Parse identifier or constants 1/0
    if (S[I] == '1') {
      ++I;
      return true;
    }
    if (S[I] == '0') {
      ++I;
      return false;
    }
    size_t start = I;
    while (I < S.size() && (isalnum(static_cast<unsigned char>(S[I])) ||
                            S[I] == '_' || S[I] == '.'))
      ++I;
    std::string tok = S.substr(start, I - start);
    if (tok.empty())
      return false;
    return TrueAPs.count(tok) != 0;
  }
};

static std::string makeAPName(int nodeId) {
  return "ap_" + std::to_string(nodeId);
}

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

    APEvaluator eval = [fn, sym, bt](const GenericEvent &E, CheckerContext &C,
                                     ProgramStateRef UseState) -> bool {
      // Predicate: __isnonnull(x)
      if (fn == "__isnonnull") {
        if (E.Symbol && E.SymbolName == sym) {
          ProgramStateRef S = UseState ? UseState : C.getState();
          ConditionTruthVal IsNull =
              C.getConstraintManager().isNull(S, E.Symbol);
          // Strict: true only when provably non-null on this path
          return IsNull.isConstrainedFalse();
        }
        return false;
      }
      // Variable-only AP: true if the current event references the same symbol
      if (fn.empty()) {
        return (!sym.empty() && E.SymbolName == sym);
      }
      // Function AP: true if this event is for that function on the bound
      // symbol
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
    return std::string("(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + " & " +
           buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Or:
    return std::string("(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + " | " +
           buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Implies:
    return std::string("(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + " -> " +
           buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Not:
    return std::string("!(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + ")";
  case LTLNodeType::Globally:
    return std::string("G(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + ")";
  case LTLNodeType::Eventually: {
    // Rewrite F φ into (¬ap_DEAD(x) & ¬ap_ENDANALYSIS(x)) U φ when φ refers to
    // a bound symbol x. Extract the symbol name if present in the child subtree
    // to parameterize sentinel APs. For simplicity, if no symbol binding found,
    // fall back to F φ.
    std::string inner = buildSpotFormulaString(node->Children[0].get(), reg);
    std::string sym;
    const LTLFormulaNode *child = node->Children[0].get();
    std::function<bool(const LTLFormulaNode *)> findSym =
        [&](const LTLFormulaNode *n) -> bool {
      if (!n)
        return false;
      if (n->Type == LTLNodeType::Atomic && !n->Binding.SymbolName.empty()) {
        sym = n->Binding.SymbolName;
        return true;
      }
      for (const auto &ch : n->Children)
        if (findSym(ch.get()))
          return true;
      return false;
    };
    findSym(child);
    if (!sym.empty()) {
      // Register sentinel APs for this symbol lazily (evaluators are generic by
      // name match)
      const std::string apDead = std::string("ap_DEAD_") + sym;
      const std::string apEnd = std::string("ap_ENDANALYSIS_") + sym;
      reg.registerAP(-100000 - (int)std::hash<std::string>{}(apDead), apDead,
                     [sym](const GenericEvent &E, CheckerContext &C,
                           ProgramStateRef UseState) -> bool {
                       if (E.Type != EventType::DeadSymbols)
                         return false;
                       // Match either by explicit event name or by mapping from
                       // symbol to DSL var name
                       if (E.SymbolName == sym)
                         return true;
                       if (E.Symbol && UseState) {
                         if (const std::string *VN =
                                 UseState->get<::GenericSymbolMap>(E.Symbol))
                           return *VN == sym;
                       }
                       return false;
                     });
      reg.registerAP(-200000 - (int)std::hash<std::string>{}(apEnd), apEnd,
                     [sym](const GenericEvent &E, CheckerContext &C,
                           ProgramStateRef UseState) -> bool {
                       if (E.Type != EventType::EndAnalysis)
                         return false;
                       if (E.SymbolName == sym)
                         return true;
                       if (E.Symbol && UseState) {
                         if (const std::string *VN =
                                 UseState->get<::GenericSymbolMap>(E.Symbol))
                           return *VN == sym;
                       }
                       return false;
                     });
      // Parenthesize the entire Until subexpression to ensure correct
      // precedence
      return std::string("((") + "!" + apDead + " & !" + apEnd + ") U (" +
             inner + "))";
    }
    return std::string("F(") + inner + ")";
  }
  case LTLNodeType::Next:
    return std::string("X(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + ")";
  case LTLNodeType::Until:
    return std::string("(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + " U " +
           buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  case LTLNodeType::Release:
    return std::string("(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + " R " +
           buildSpotFormulaString(node->Children[1].get(), reg) + ")";
  }
  return "1";
}

} // namespace

SpotBuildResult dsl::buildSpotMonitorFromDSL(const LTLFormulaBuilder &Builder) {
  SpotBuildResult R;

  // Translate DSL → infix PSL and register AP evaluators.
  const LTLFormulaNode *root = Builder.getRootNode();
  std::string infix = buildSpotFormulaString(root, R.Registry);
  if (infix.empty())
    infix = "G 1";
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][SPOT] PSL formula: " << infix << "\n";
  }

  // Internally append an End AP evaluator so the monitor can observe
  // function-end. The End AP is true only on EndFunction events. It is not
  // referenced by the DSL formula yet.
  {
    const std::string apEnd = "ap_END";
    APEvaluator endEval = [](const GenericEvent &E, CheckerContext &C,
                             ProgramStateRef) -> bool {
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
  if (edslDebugEnabled() && R.Monitor) {
    auto dict = R.Monitor->get_dict();
    llvm::errs() << "[EDSL][SPOT] automaton: states=" << R.Monitor->num_states()
                 << "\n";
    for (unsigned s = 0; s < R.Monitor->num_states(); ++s) {
      unsigned outdeg = 0;
      for (auto &t : R.Monitor->out(s))
        (void)t, ++outdeg;
      llvm::errs() << "  state " << s << ": out=" << outdeg << "\n";
      for (auto &t : R.Monitor->out(s)) {
        std::string condStr = spot::bdd_format_formula(dict, t.cond);
        llvm::errs() << "    -> " << t.dst << " if " << condStr << "\n";
      }
    }
  }
  return R;
}

std::unique_ptr<DSLMonitor>
DSLMonitor::create(std::unique_ptr<PropertyDefinition> Property,
                   const CheckerBase *O) {
  auto fb = Property->getFormulaBuilder();
  auto res = dsl::buildSpotMonitorFromDSL(fb);
  auto M = std::make_unique<DSLMonitor>(
      std::move(res.Monitor), std::move(res.Registry), O, std::move(fb));
  // Try to detect top-level G(Implies(A,B)) and build RHS-only monitor
  const LTLFormulaNode *root = M->getFormulaBuilder().getRootNode();
  if (root && root->Type == LTLNodeType::Globally &&
      root->Children.size() == 1) {
    const LTLFormulaNode *imp = root->Children[0].get();
    if (imp && imp->Type == LTLNodeType::Implies && imp->Children.size() == 2) {
      M->TopLevelAntecedent = imp->Children[0].get();
      M->TopLevelConsequent = imp->Children[1].get();
      // Build a temporary builder for RHS only
      LTLFormulaBuilder rhsB = M->getFormulaBuilder();
      // Create a shallow copy that uses the RHS as root: we rely on
      // buildSpotFormulaString walking from that node We cheat by building a
      // separate SpotBuildResult with the same registry (AP names must match)
      APRegistry dummy; // ignored, we will reuse M->Registry for evaluation
      std::string rhsPSL = [&]() {
        APRegistry tmpReg;
        return buildSpotFormulaString(M->TopLevelConsequent, tmpReg);
      }();
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] RHS PSL: " << rhsPSL << "\n";
      }
      // Parse RHS PSL into its own monitor graph (share dict with main graph by
      // re-parsing)
      spot::parsed_formula pf = spot::parse_infix_psl(rhsPSL);
      if (!pf.format_errors(std::cerr)) {
        spot::translator trans;
        trans.set_type(spot::postprocessor::Monitor);
        trans.set_pref(spot::postprocessor::Deterministic);
        M->SpotGraphRHS = trans.run(pf.f);
      }
    }
  }
  return M;
}

namespace {
// Helper to step SPOT with valuations built from a specific ProgramStateRef
struct SpotStepper {
  static void step(spot::twa_graph_ptr &Graph, APRegistry &Registry,
                   std::map<std::string, int> &ApVarIds, int &CurrentState,
                   const CheckerBase *Owner, const GenericEvent &event,
                   CheckerContext &C, ProgramStateRef UseState,
                   const LTLFormulaBuilder &FormulaBuilder) {
    if (!Graph)
      return;
    if (ApVarIds.empty()) {
      for (const auto &kv : Registry.getEvaluators()) {
        int var = Graph->register_ap(kv.first);
        ApVarIds[kv.first] = var;
      }
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] APs registered: ";
        bool first = true;
        for (auto &kv : ApVarIds) {
          if (!first)
            llvm::errs() << ", ";
          first = false;
          llvm::errs() << kv.first << "->" << kv.second;
        }
        llvm::errs() << "\n";
      }
    }
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][SPOT] event: type=" << (int)event.Type
                   << ", fn=" << event.FunctionName
                   << ", sym=" << event.SymbolName << "\n";
    }
    std::set<std::string> trueAPs;
    for (const auto &kv : Registry.getEvaluators()) {
      if (kv.second(event, C, UseState))
        trueAPs.insert(kv.first);
    }
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][SPOT] AP valuation: ";
      for (const auto &kv : Registry.getEvaluators()) {
        const std::string &ap = kv.first;
        bool val = trueAPs.count(ap);
        int nodeId = -1;
        for (const auto &m : Registry.getMapping())
          if (m.second == ap) {
            nodeId = m.first;
            break;
          }
        const LTLFormulaNode *node = FormulaBuilder.getNodeByID(nodeId);
        std::string who = node ? (node->FunctionName.empty()
                                      ? node->Binding.SymbolName
                                      : node->FunctionName + "(" +
                                            node->Binding.SymbolName + ")")
                               : std::string("<synthetic>");
        llvm::errs() << ap << "=" << (val ? "T" : "F") << "[" << who << "] ";
      }
      llvm::errs() << "\n";
    }
    bdd valuation = bddtrue;
    for (const auto &kv : Registry.getEvaluators()) {
      const std::string &ap = kv.first;
      int var = ApVarIds[ap];
      valuation = bdd_and(valuation, trueAPs.count(ap) ? bdd_ithvar(var)
                                                       : bdd_nithvar(var));
    }
    unsigned ns = Graph->num_states();
    if (CurrentState >= (int)ns)
      CurrentState = 0;
    int nextState = CurrentState;
    bool matched = false;
    if (edslDebugEnabled()) {
      auto dict = Graph->get_dict();
      std::string cube = spot::bdd_format_formula(dict, valuation);
      llvm::errs() << "[EDSL][SPOT] valuation cube: " << cube << "\n";
      llvm::errs() << "[EDSL][SPOT] outgoing from state " << CurrentState
                   << ":\n";
      for (auto &t : Graph->out(CurrentState)) {
        std::string condStr = spot::bdd_format_formula(dict, t.cond);
        llvm::errs() << "  cond=" << condStr << " -> dst=" << t.dst << "\n";
      }
    }
    for (auto &t : Graph->out(CurrentState)) {
      bdd sat = bdd_restrict(t.cond, valuation);
      if (sat != bddfalse) {
        nextState = (int)t.dst;
        matched = true;
        break;
      }
    }
    if (matched) {
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] state " << CurrentState << " -> "
                     << nextState << "\n";
      }
      CurrentState = nextState;
      // For sentinel-driven safety, emit on DeadSymbols/EndAnalysis when
      // obligation is pending.
      if (event.Type == EventType::DeadSymbols ||
          event.Type == EventType::EndAnalysis) {
        bool pending = false;
        if (event.Symbol && UseState) {
          if (UseState->contains<::TrackedSymbols>(event.Symbol)) {
            if (const ::SymbolState *CurPtr =
                    UseState->get<::SymbolStates>(event.Symbol))
              pending = (*CurPtr == ::SymbolState::Active);
          }
        }
        if (pending) {
          ExplodedNode *ErrorNode = C.generateErrorNode(UseState);
          if (ErrorNode) {
            static const BugType BT{Owner, "temporal_violation",
                                    "EmbeddedDSLMonitor"};
            std::string msg =
                (event.Type == EventType::DeadSymbols)
                    ? "resource not destroyed (violates exactly-once)"
                    : "resource not destroyed (violates exactly-once)";
            if (event.Symbol)
              msg += std::string(" (internal symbol: sym_") +
                     std::to_string(event.Symbol->getSymbolID()) + ")";
            auto R =
                std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
            if (event.Symbol)
              R->markInteresting(event.Symbol);
            C.emitReport(std::move(R));
          }
        }
      }
    } else {
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] no transition satisfied from state "
                     << CurrentState << "; temporal violation; event fn='"
                     << event.FunctionName << "' sym='" << event.SymbolName
                     << "'" << "\n";
      }
      // Ignore 'no transition' cases to avoid false positives
    }
  }
};
} // namespace

void DSLMonitor::handleEvent(const GenericEvent &event, CheckerContext &C) {
  ExplodedNode *Pred = C.getPredecessor();
  ProgramStateRef Base = C.getState();
  struct Branch {
    ProgramStateRef S;
    const NoteTag *Tag;
  };
  llvm::SmallVector<Branch, 2> branches;

  auto addBranch = [&](ProgramStateRef S, const NoteTag *Tag = nullptr) {
    if (!S)
      return;
    branches.push_back({S, Tag});
  };

  switch (event.Type) {
  case EventType::PostCall: {
    if (event.Symbol && !event.FunctionName.empty() &&
        !event.SymbolName.empty()) {
      BindingType BT =
          EventCreator.getBindingType(event.FunctionName, event.SymbolName);
      if (BT == BindingType::ReturnValue) {
        if (isSymbolUsedInIsNonNull(event.SymbolName)) {
          if (edslDebugEnabled())
            llvm::errs() << "[EDSL] create: " << event.FunctionName << "("
                         << event.SymbolName << ") -> split on non-null\n";
          SValBuilder &SVB = C.getSValBuilder();
          SVal SymV = SVB.makeLoc(event.Symbol);
          QualType PtrTy = event.Symbol->getType();
          SVal Null = SVB.makeZeroVal(PtrTy);
          SVal NE =
              SVB.evalBinOp(Base, BO_NE, SymV, Null, C.getASTContext().BoolTy);
          if (auto D = NE.getAs<DefinedSVal>()) {
            ProgramStateRef STrue, SFalse;
            std::tie(STrue, SFalse) =
                C.getConstraintManager().assumeDual(Base, *D);
            if (STrue) {
              auto St = STrue->set<::SymbolStates>(event.Symbol,
                                                   ::SymbolState::Active);
              St = St->set<::GenericSymbolMap>(event.Symbol, event.SymbolName);
              St = St->add<::TrackedSymbols>(event.Symbol);
              std::string internal =
                  "sym_" + std::to_string(event.Symbol->getSymbolID());
              std::string var = event.SymbolName.empty() ? std::string("x")
                                                         : event.SymbolName;
              std::string note =
                  std::string("symbol \"") + var +
                  "\" is bound here (internal symbol: " + internal + ")";
              const NoteTag *NT = C.getNoteTag([note]() { return note; });
              addBranch(St, NT);
            }
            if (SFalse) {
              auto Sf = SFalse->set<::SymbolStates>(
                  event.Symbol, ::SymbolState::Uninitialized);
              Sf = Sf->set<::GenericSymbolMap>(event.Symbol, event.SymbolName);
              addBranch(Sf);
            }
            break;
          }
        }
        if (edslDebugEnabled())
          llvm::errs() << "[EDSL] create: " << event.FunctionName << "("
                       << event.SymbolName
                       << ") -> no split (no IsNonNull AP)\n";
        auto S0 = Base->set<::SymbolStates>(event.Symbol,
                                            ::SymbolState::Uninitialized);
        S0 = S0->set<::GenericSymbolMap>(event.Symbol, event.SymbolName);
        addBranch(S0);
      }
    }
    break;
  }
  case EventType::PreCall: {
    if (event.Symbol && !event.FunctionName.empty() &&
        !event.SymbolName.empty()) {
      BindingType BT =
          EventCreator.getBindingType(event.FunctionName, event.SymbolName);
      if (BT == BindingType::FirstParameter ||
          BT == BindingType::NthParameter) {
        const ::SymbolState *CurPtr = Base->get<::SymbolStates>(event.Symbol);
        ::SymbolState Cur = CurPtr ? *CurPtr : ::SymbolState::Uninitialized;
        if (Cur == ::SymbolState::Uninitialized &&
            isSymbolUsedInIsNonNull(event.SymbolName)) {
          SValBuilder &SVB = C.getSValBuilder();
          SVal SymV = SVB.makeLoc(event.Symbol);
          QualType PtrTy = event.Symbol->getType();
          SVal Null = SVB.makeZeroVal(PtrTy);
          SVal NE =
              SVB.evalBinOp(Base, BO_NE, SymV, Null, C.getASTContext().BoolTy);
          if (auto D = NE.getAs<DefinedSVal>()) {
            ProgramStateRef STrue, SFalse;
            std::tie(STrue, SFalse) =
                C.getConstraintManager().assumeDual(Base, *D);
            if (STrue) {
              auto Sa = STrue->set<::SymbolStates>(event.Symbol,
                                                   ::SymbolState::Active);
              Sa = Sa->set<::GenericSymbolMap>(event.Symbol, event.SymbolName);
              Sa = Sa->add<::TrackedSymbols>(event.Symbol);
              Sa = Sa->set<::SymbolStates>(event.Symbol,
                                           ::SymbolState::Inactive);
              // keep GenericSymbolMap and TrackedSymbols to allow double-free
              // detection
              addBranch(Sa);
            }
            if (SFalse)
              addBranch(SFalse);
            break;
          }
        }
        const ::SymbolState *CurPtr2 = Base->get<::SymbolStates>(event.Symbol);
        ::SymbolState Cur2 = CurPtr2 ? *CurPtr2 : ::SymbolState::Uninitialized;
        if (Cur2 == ::SymbolState::Inactive) {
          // Double-free: free called on already inactive resource
          ExplodedNode *ErrorNode = C.generateErrorNode(Base);
          if (ErrorNode) {
            static const BugType BT{Owner, "temporal_violation",
                                    "EmbeddedDSLMonitor"};
            std::string msg =
                "resource destroyed twice (violates exactly-once)";
            if (event.Symbol)
              msg += std::string(" (internal symbol: sym_") +
                     std::to_string(event.Symbol->getSymbolID()) + ")";
            auto R =
                std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
            R->markInteresting(event.Symbol);
            C.emitReport(std::move(R));
          }
        }
        if (Cur2 == ::SymbolState::Active) {
          auto S1 =
              Base->set<::SymbolStates>(event.Symbol, ::SymbolState::Inactive);
          // keep GenericSymbolMap and TrackedSymbols to allow double-free
          // detection
          addBranch(S1);
        }
      }
    }
    break;
  }
  case EventType::DeadSymbols: {
    addBranch(Base);
    break;
  }
  case EventType::PointerEscape: {
    if (event.Symbol) {
      auto S1 = Base->remove<::TrackedSymbols>(event.Symbol);
      addBranch(S1);
    }
    break;
  }
  case EventType::EndFunction: {
    addBranch(Base);
    break;
  }
  case EventType::EndAnalysis: {
    addBranch(Base);
    break;
  }
  }

  if (branches.empty())
    addBranch(Base);

  // Step SPOT for each branch prior to committing transitions
  for (auto &br : branches) {
    SpotStepper::step(SpotGraph, Registry, ApVarIds, CurrentState, Owner, event,
                      C, br.S, FormulaBuilder);
    // If RHS-only monitor exists and antecedent holds in this branch, step RHS
    if (SpotGraphRHS && TopLevelAntecedent) {
      // Evaluate antecedent by reusing evaluators mapped from the original
      // Builder
      std::set<std::string> trueAPs;
      for (const auto &kv : Registry.getEvaluators()) {
        if (kv.second(event, C, br.S))
          trueAPs.insert(kv.first);
      }
      // Heuristic: antecedent is in terms of APs; check if all atoms under A
      // are satisfied Make recursive predicate explicit to avoid auto recursion
      // issue
      std::function<bool(const LTLFormulaNode *)> isTrue;
      isTrue = [&](const LTLFormulaNode *n) -> bool {
        if (!n)
          return false;
        switch (n->Type) {
        case LTLNodeType::Atomic: {
          auto it = Registry.getMapping().find(n->NodeID);
          if (it == Registry.getMapping().end())
            return false;
          return trueAPs.count(it->second) != 0;
        }
        case LTLNodeType::And:
          return isTrue(n->Children[0].get()) && isTrue(n->Children[1].get());
        case LTLNodeType::Or:
          return isTrue(n->Children[0].get()) || isTrue(n->Children[1].get());
        case LTLNodeType::Not:
          return !isTrue(n->Children[0].get());
        default: {
          // Fallback: require all atoms in subtree to be true
          for (const auto &ch : n->Children)
            if (!isTrue(ch.get()))
              return false;
          return true;
        }
        }
      };
      if (isTrue(TopLevelAntecedent)) {
        // Initialize RHS AP ids lazily
        if (ApVarIdsRHS.empty()) {
          for (const auto &kv : Registry.getEvaluators()) {
            int var = SpotGraphRHS->register_ap(kv.first);
            ApVarIdsRHS[kv.first] = var;
          }
        }
        SpotStepper::step(SpotGraphRHS, Registry, ApVarIdsRHS, CurrentStateRHS,
                          Owner, event, C, br.S, FormulaBuilder);
      }
    }
  }

  // Emit at most two children from the same predecessor
  for (auto &br : branches) {
    C.addTransition(br.S, Pred, br.Tag);
  }
}

size_t DSLMonitor::getTrackedCount(ProgramStateRef S) const {
  return (size_t)std::distance(S->get<::TrackedSymbols>().begin(),
                               S->get<::TrackedSymbols>().end());
}

std::vector<unsigned> DSLMonitor::getTrackedSymbolIDs(ProgramStateRef S) const {
  std::vector<unsigned> ids;
  for (auto Sym : S->get<::TrackedSymbols>())
    ids.push_back(Sym->getSymbolID());
  return ids;
}

std::vector<SymbolRef> DSLMonitor::getTrackedSymbols(ProgramStateRef S) const {
  std::vector<SymbolRef> syms;
  for (auto Sym : S->get<::TrackedSymbols>())
    syms.push_back(Sym);
  return syms;
}

bool DSLMonitor::isTracked(ProgramStateRef S, SymbolRef Sym) const {
  return S->contains<::TrackedSymbols>(Sym);
}

bool DSLMonitor::isActive(ProgramStateRef S, SymbolRef Sym) const {
  if (const ::SymbolState *CurPtr = S->get<::SymbolStates>(Sym))
    return *CurPtr == ::SymbolState::Active;
  return false;
}

void DSLMonitor::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                                  ExprEngine &Eng) const {
  (void)G;
  (void)BR;
  (void)Eng;
}
