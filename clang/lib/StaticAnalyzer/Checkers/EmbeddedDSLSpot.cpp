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
// Prefer the smallest (deepest) labeled node in a subtree, with optional
// preference for specific temporal/boolean node types.
static std::string
selectLabelFromSubtree(const LTLFormulaNode *root,
                       std::initializer_list<LTLNodeType> preferredTypes) {
  if (!root)
    return std::string();
  llvm::SmallVector<LTLNodeType, 4> prefer(preferredTypes.begin(),
                                           preferredTypes.end());
  struct Cand {
    const LTLFormulaNode *N;
    int D;
  };
  std::vector<Cand> pref, any;
  std::function<void(const LTLFormulaNode *, int)> dfs =
      [&](const LTLFormulaNode *n, int d) {
        if (!n)
          return;
        if (!n->DiagnosticLabel.empty()) {
          bool isPref =
              std::find(prefer.begin(), prefer.end(), n->Type) != prefer.end();
          if (isPref)
            pref.push_back({n, d});
          any.push_back({n, d});
        }
        for (const auto &ch : n->Children)
          dfs(ch.get(), d + 1);
      };
  dfs(root, 0);
  auto pickDeepest =
      [](const std::vector<Cand> &vec) -> const LTLFormulaNode * {
    const LTLFormulaNode *best = nullptr;
    int bestD = -1;
    for (const auto &c : vec) {
      if (c.D > bestD) {
        bestD = c.D;
        best = c.N;
      }
    }
    return best;
  };
  if (!pref.empty()) {
    if (auto *n = pickDeepest(pref))
      return n->DiagnosticLabel;
  }
  if (!any.empty()) {
    if (auto *n = pickDeepest(any))
      return n->DiagnosticLabel;
  }
  return std::string();
}

// (Removed unused BoolParser)

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
    // Capture node for matcher evaluation
    const LTLFormulaNode *const capturedNode = node;

    APEvaluator eval = [fn, sym, bt, ap,
                        capturedNode](const GenericEvent &E, CheckerContext &C,
                                      ProgramStateRef UseState) -> bool {
      // Check if this is a non-null binding type
      bool isNonNull = isNonNullBinding(bt);
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][AP_EVAL] Evaluating AP " << ap << " (fn='" << fn
                     << "', sym='" << sym << "', bt=" << (int)bt
                     << ", isNonNull=" << isNonNull << ")\n";
        llvm::errs() << "[EDSL][AP_EVAL]   Event: fn='" << E.FunctionName
                     << "', sym='" << E.SymbolName
                     << "', hasSymbol=" << (E.Symbol ? "yes" : "no") << "\n";
      }
      if (isNonNull) {
        // For non-null binding types, we just need to check if the symbol
        // exists. The function name matching is already handled during event
        // creation by the APDrivenEventCreator, so we don't need to check it
        // again here.
        if (E.Symbol && E.SymbolName == sym) {
          if (edslDebugEnabled()) {
            llvm::errs() << "[EDSL][AP_EVAL]   Non-null binding: symbol "
                            "matches, result=TRUE\n";
          }
          return true;
        }
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][AP_EVAL]   Non-null binding failed: E.Symbol="
                       << (E.Symbol ? "yes" : "no") << ", E.SymbolName='"
                       << E.SymbolName << "' != sym='" << sym << "'\n";
        }
        return false;
      }
      // Gate by function name or matcher (with debug):
      if (!fn.empty()) {
        bool gateOK = (E.FunctionName == fn);
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][MATCH] ap=" << ap
                       << " name_eq=" << (gateOK ? "T" : "F") << " expected='"
                       << fn << "' got='" << E.FunctionName << "' sym='"
                       << E.SymbolName << "'\n";
        }
        if (!gateOK)
          return false;
      } else if (capturedNode && capturedNode->HasCallMatcher) {
        // Only fall back to matcher if no stable function name is provided
        bool ok = capturedNode->matchOrigin(E.OriginExpr, C.getASTContext());
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][MATCH] ap=" << ap
                       << " matcher=" << (ok ? "T" : "F")
                       << " origin=" << (const void *)E.OriginExpr << " sym='"
                       << E.SymbolName << "'\n";
        }
        if (!ok)
          return false;
      } else {
        // Variable-only AP (no matcher, no function name)
        bool varOK = (!sym.empty() && E.SymbolName == sym);
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][MATCH] ap=" << ap
                       << " var_eq=" << (varOK ? "T" : "F") << " expected='"
                       << sym << "' got='" << E.SymbolName << "'\n";
        }
        return varOK;
      }
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
  case LTLNodeType::Eventually:
    return std::string("F(") +
           buildSpotFormulaString(node->Children[0].get(), reg) + ")";
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
      O, std::move(res.Monitor), std::move(res.Registry), O, std::move(fb));
  // No need for RHS/LHS separation since formula uses Next operator
  // Note: Function bindings are already registered in the DSLMonitor
  // constructor

  return M;
}

namespace {
// Helper to step SPOT with valuations built from a specific ProgramStateRef
struct SpotStepper {
  static llvm::SmallVector<DSLMonitor::EventResult, 2>
  step(spot::twa_graph_ptr &Graph, APRegistry &Registry,
       std::map<std::string, int> &ApVarIds, int &CurrentState,
       const CheckerBase *Owner, const GenericEvent &event, CheckerContext &C,
       ProgramStateRef UseState, const LTLFormulaBuilder &FormulaBuilder) {
    llvm::SmallVector<DSLMonitor::EventResult, 2> results;
    // SpotGraph is guaranteed to be non-null by constructor assertion
    // Double-free detection is now handled directly in handleEvent
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
      llvm::errs() << "[EDSL][SPOT] ===== SPOT EVALUATION START =====\n";
      llvm::errs() << "[EDSL][SPOT] Event: type=" << (int)event.Type
                   << ", fn=" << event.FunctionName
                   << ", sym=" << event.SymbolName << "\n";
      llvm::errs() << "[EDSL][SPOT] Current automaton state: " << CurrentState
                   << "\n";
      llvm::errs() << "[EDSL][SPOT] Total automaton states: "
                   << Graph->num_states() << "\n";
    }
    std::set<std::string> trueAPs;
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][SPOT] Evaluating "
                   << Registry.getEvaluators().size() << " APs:\n";
    }

    for (const auto &kv : Registry.getEvaluators()) {
      const std::string &ap = kv.first;
      bool val = kv.second(event, C, UseState);
      if (val)
        trueAPs.insert(ap);

      if (edslDebugEnabled()) {
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
        llvm::errs() << "[EDSL][SPOT]   AP " << ap << " (node " << nodeId
                     << ") = " << (val ? "TRUE" : "FALSE") << " [" << who
                     << "]\n";
      }
    }

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][SPOT] True APs: [";
      bool first = true;
      for (const auto &ap : trueAPs) {
        if (!first)
          llvm::errs() << ", ";
        llvm::errs() << ap;
        first = false;
      }
      llvm::errs() << "]\n";
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
      llvm::errs() << "[EDSL][SPOT] BDD valuation cube: " << cube << "\n";
      llvm::errs() << "[EDSL][SPOT] Evaluating transitions from state "
                   << CurrentState << ":\n";

      int transitionCount = 0;
      for (auto &t : Graph->out(CurrentState)) {
        std::string condStr = spot::bdd_format_formula(dict, t.cond);
        llvm::errs() << "[EDSL][SPOT]   Transition " << transitionCount++
                     << ": cond=" << condStr << " -> dst=" << t.dst << "\n";
      }
    }
    int transitionIndex = 0;
    for (auto &t : Graph->out(CurrentState)) {
      bdd sat = bdd_restrict(t.cond, valuation);

      if (edslDebugEnabled()) {
        auto dict = Graph->get_dict();
        std::string condStr = spot::bdd_format_formula(dict, t.cond);
        std::string satStr = spot::bdd_format_formula(dict, sat);
        llvm::errs() << "[EDSL][SPOT]   Checking transition " << transitionIndex
                     << ": cond=" << condStr << " -> dst=" << t.dst
                     << " (restricted=" << satStr << ")\n";
      }

      if (sat != bddfalse) {
        nextState = (int)t.dst;
        matched = true;
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][SPOT]   ✓ Transition " << transitionIndex
                       << " SATISFIED! Moving from state " << CurrentState
                       << " to state " << nextState << "\n";
        }
        break;
      } else {
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][SPOT]   ✗ Transition " << transitionIndex
                       << " NOT satisfied\n";
        }
      }
      transitionIndex++;
    }

    if (matched) {
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] ===== STATE TRANSITION =====\n";
        llvm::errs() << "[EDSL][SPOT] State " << CurrentState << " -> "
                     << nextState << "\n";
        llvm::errs() << "[EDSL][SPOT] ==============================\n";
      }
      CurrentState = nextState;
      // For sentinel-driven safety, emit on DeadSymbols/EndAnalysis when
      // obligation is pending.
      if (event.Type == EventType::DeadSymbols ||
          event.Type == EventType::EndAnalysis) {
        bool pending = false;
        if (event.Symbol && UseState) {
          if (dsl::containsTrackedSymbol(UseState, event.Symbol)) {
            if (const ::SymbolState *CurPtr =
                    dsl::getSymbolState(UseState, event.Symbol))
              pending = (*CurPtr == ::SymbolState::Active);
          }
        }
        if (pending) {
          ExplodedNode *ErrorNode = C.generateErrorNode(UseState);
          if (ErrorNode) {
            static const BugType BT{Owner, "temporal_violation",
                                    "EmbeddedDSLMonitor"};
            // Prefer label from RHS subtree: deepest labeled Eventually/Until,
            // else any
            std::string msg = selectLabelFromSubtree(
                nullptr, {LTLNodeType::Eventually, LTLNodeType::Until});
            if (msg.empty())
              msg = "resource not destroyed (violates exactly-once)";
            if (event.Symbol)
              msg += std::string(" (internal symbol: sym_") +
                     std::to_string(event.Symbol->getSymbolID()) + ")";
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL][REPORT] leak/end violation: " << msg
                           << "\n";
            }
            // Use deferred approach - return bug report info instead of
            // creating directly
            results.emplace_back(DSLMonitor::DeferredErrorResult(
                msg, "temporal_violation", "EmbeddedDSLMonitor", event.Symbol));
            return results;
          }
        }
      }
    } else {
      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][SPOT] ===== NO TRANSITION MATCHED =====\n";
        llvm::errs() << "[EDSL][SPOT] No transition satisfied from state "
                     << CurrentState << "\n";
        llvm::errs() << "[EDSL][SPOT] Event: fn='" << event.FunctionName
                     << "' sym='" << event.SymbolName << "'\n";
        llvm::errs() << "[EDSL][SPOT] This indicates a temporal violation!\n";
        llvm::errs() << "[EDSL][SPOT] ======================================\n";
      }
      // Leak detection is now handled in the checker's checkDeadSymbols method
      // and deferred to checkEndFunction for proper error node creation
    }
    return results;
  }
};
} // namespace

// Overloads that bridge specific events to the existing GenericEvent handler
void DSLMonitor::handleEvent(const PostCallEvent &E, CheckerContext &C) {
  GenericEvent GE{
      EventType::PostCall, E.FunctionName, E.SymbolName,     E.Symbol,
      E.Location,          E.OriginExpr,   E.DerivedBinding, nullptr};
  return handleEvent(GE, C);
}

void DSLMonitor::handleEvent(const PreCallEvent &E, CheckerContext &C) {
  GenericEvent GE{EventType::PreCall, E.FunctionName, E.SymbolName,
                  E.Symbol,           E.Location,     E.OriginExpr,
                  E.DerivedBinding,   nullptr};
  return handleEvent(GE, C);
}

void DSLMonitor::handleEvent(const DeadSymbolsEvent &E, CheckerContext &C) {
  GenericEvent GE{EventType::DeadSymbols,
                  "",
                  E.SymbolName,
                  E.Symbol,
                  SourceLocation(),
                  nullptr,
                  BindingType::ReturnValue,
                  nullptr};
  return handleEvent(GE, C);
}

void DSLMonitor::handleEvent(const EndFunctionEvent &, CheckerContext &C) {
  GenericEvent GE{
      EventType::EndFunction,   "",     "", nullptr, SourceLocation(), nullptr,
      BindingType::ReturnValue, nullptr};
  return handleEvent(GE, C);
}

void DSLMonitor::handleEvent(const EndAnalysisEvent &, CheckerContext &C) {
  GenericEvent GE{
      EventType::EndAnalysis,   "",     "", nullptr, SourceLocation(), nullptr,
      BindingType::ReturnValue, nullptr};
  return handleEvent(GE, C);
}

void DSLMonitor::handleEvent(const PointerEscapeEvent &E, CheckerContext &C) {
  GenericEvent GE{EventType::PointerEscape,
                  "",
                  E.SymbolName,
                  E.Symbol,
                  SourceLocation(),
                  nullptr,
                  BindingType::ReturnValue,
                  nullptr};
  return handleEvent(GE, C);
}

void DSLMonitor::handleEvent(const BindEvent &E, CheckerContext &C) {
  GenericEvent GE{EventType::Bind,
                  "",
                  E.SymbolName,
                  E.Symbol,
                  SourceLocation(),
                  E.StoreExpr,
                  BindingType::FirstParameter,
                  E.BoundRegion};
  return handleEvent(GE, C);
}

void DSLMonitor::handleEventResult(const DSLMonitor::EventResult &result,
                                   CheckerContext &C) {
  if (auto *NonErrorResult = std::get_if<DSLMonitor::NonErrorResult>(&result)) {
    if (dsl::edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CHECKER] adding transition for NonErrorResult\n";
    }
    C.addTransition(NonErrorResult->State, C.getPredecessor(),
                    NonErrorResult->NoteTag);
  } else if (auto DeferredErrorResult =
                 std::get_if<DSLMonitor::DeferredErrorResult>(&result)) {
    if (dsl::edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CHECKER] creating deferred BugReport\n";
    }
    static const BugType BT{Owner, DeferredErrorResult->BugTypeName,
                            DeferredErrorResult->BugTypeCategory};
    ExplodedNode *ErrorNode = C.generateErrorNode();
    if (ErrorNode) {
      auto BR = std::make_unique<PathSensitiveBugReport>(
          BT, DeferredErrorResult->Message, ErrorNode);
      if (DeferredErrorResult->Symbol)
        BR->markInteresting(DeferredErrorResult->Symbol);
      C.emitReport(std::move(BR));
    } else {
      if (dsl::edslDebugEnabled()) {
        llvm::errs() << "[EDSL][CHECKER] failed to create ErrorNode for "
                        "deferred BugReport\n";
      }
    }
  } else {
    if (dsl::edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CHECKER] unknown EventResult type\n";
    }
  }
}

void DSLMonitor::handleEvent(const GenericEvent &event, CheckerContext &C) {
  ExplodedNode *Pred = C.getPredecessor();
  ProgramStateRef Base = C.getState();

  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][HANDLE] event type=" << (int)event.Type << " fn='"
                 << event.FunctionName << "' sym='" << event.SymbolName
                 << "' pred=" << Pred
                 << " base_state=" << (const void *)Base.get() << "\n";
  }

  // Step 1: Handle state splitting (if needed) and determine main state
  ProgramStateRef MainState = Base;

  if (edslDebugEnabled()) {
    llvm::errs()
        << "[EDSL][HANDLE] Step 1: State splitting check for event type="
        << (int)event.Type << " symbol=" << (event.Symbol ? "yes" : "no")
        << " symbolName='" << event.SymbolName << "'\n";
  }

  // Step 1.5: Update symbol-formula mapping if we have a symbol and formula
  // variable name
  if (event.Symbol && !event.SymbolName.empty()) {
    MainState =
        dsl::setSymbolFormulaMapping(MainState, event.Symbol, event.SymbolName);
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][HANDLE] Updated symbol-formula mapping: sym_id="
                   << event.Symbol->getSymbolID() << " -> var='"
                   << event.SymbolName << "'\n";
    }
  }

  if (event.Type == EventType::PostCall && event.Symbol &&
      !event.SymbolName.empty()) {
    BindingType BT = event.DerivedBinding;
    bool needsSplit = isSymbolUsedInIsNonNull(event.SymbolName);
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][HANDLE] PostCall event: symbolName='"
                   << event.SymbolName << "' BT=" << (int)BT
                   << " isSymbolUsedInIsNonNull=" << needsSplit
                   << " functionName='" << event.FunctionName << "'\n";
    }

    // Always add symbols to tracked set for PostCall events with ReturnValue
    // binding
    if (BT == BindingType::ReturnValue ||
        BT == BindingType::ReturnValueNonNull) {
      if (needsSplit) {
        // State splitting needed - check for non-null constraint
        SValBuilder &SVB = C.getSValBuilder();
        SVal SymV = SVB.makeLoc(event.Symbol);
        const Expr *OriginExpr = llvm::dyn_cast_or_null<Expr>(event.OriginExpr);
        QualType PtrTy =
            OriginExpr ? OriginExpr->getType() : event.Symbol->getType();
        SVal Null = SVB.makeZeroVal(PtrTy);
        SVal NE =
            SVB.evalBinOp(Base, BO_NE, SymV, Null, C.getASTContext().BoolTy);

        if (auto D = NE.getAs<DefinedSVal>()) {
          ProgramStateRef STrue, SFalse;
          std::tie(STrue, SFalse) =
              C.getConstraintManager().assumeDual(Base, *D);

          if (STrue) {
            // Non-null state is feasible - this becomes our main state
            MainState =
                dsl::setSymbolState(STrue, event.Symbol, ::SymbolState::Active);
            MainState = dsl::addTrackedSymbol(MainState, event.Symbol);
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL][HANDLE] Added symbol to tracked set "
                              "(non-null branch): "
                           << event.SymbolName << "\n";
            }
          } else {
            // Non-null state is not feasible - early return
            if (edslDebugEnabled()) {
              llvm::errs() << "[EDSL][HANDLE] Non-null state not feasible, "
                              "early return\n";
            }
            return;
          }

          if (SFalse) {
            // Create null branch
            auto Sf = dsl::setSymbolState(SFalse, event.Symbol,
                                          ::SymbolState::Uninitialized);
            C.addTransition(Sf, Pred);
          }
        }
      } else {
        // No state splitting needed, but still track the symbol
        MainState = dsl::addTrackedSymbol(MainState, event.Symbol);
        MainState =
            dsl::setSymbolState(MainState, event.Symbol, ::SymbolState::Active);
        if (edslDebugEnabled()) {
          llvm::errs()
              << "[EDSL][HANDLE] Added symbol to tracked set (no split): "
              << event.SymbolName << "\n";
        }
      }
    }
  }

  // Handle PreCall events (like free) - remove symbols from tracking
  if (event.Type == EventType::PreCall && event.Symbol &&
      !event.SymbolName.empty()) {
    BindingType BT = event.DerivedBinding;
    if (BT == BindingType::FirstParameter || BT == BindingType::NthParameter) {
      // Check for double-free before removing from tracked set
      const ::SymbolState *CurPtr =
          dsl::getSymbolState(MainState, event.Symbol);
      if (CurPtr && *CurPtr == ::SymbolState::Inactive) {
        // Double-free detected - create error node and return early
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][HANDLE] Double-free detected for symbol: "
                       << event.SymbolName << "\n";
        }
        ExplodedNode *ErrorNode = C.generateErrorNode(MainState);
        if (ErrorNode) {
          static const BugType BT{ContainingChecker, "temporal_violation",
                                  "EmbeddedDSLMonitor"};
          std::string msg = "resource destroyed twice (violates exactly-once)";
          if (event.Symbol)
            msg += std::string(" (internal symbol: sym_") +
                   std::to_string(event.Symbol->getSymbolID()) + ")";
          auto R = std::make_unique<PathSensitiveBugReport>(BT, msg, ErrorNode);
          C.emitReport(std::move(R));
        }
        return;
      } else {
        // First free - set symbol state to Inactive and remove from tracked set
        MainState = dsl::setSymbolState(MainState, event.Symbol,
                                        ::SymbolState::Inactive);
        MainState = dsl::removeTrackedSymbol(MainState, event.Symbol);
        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][HANDLE] Set symbol to Inactive and removed "
                          "from tracked set (freed): "
                       << event.SymbolName << "\n";
        }
      }
    }
  }

  // Step 2: Do SPOT stepping on the main state
  llvm::SmallVector<DSLMonitor::EventResult, 2> spotResults;
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][HANDLE] Step 2: SPOT stepping for symbol="
                 << (event.Symbol ? "yes" : "no") << "\n";
  }
  if (event.Symbol) {
    // Get current automaton state from GDM
    int currentState = 0;
    if (const int *statePtr = dsl::getAutomatonState(MainState, event.Symbol)) {
      currentState = *statePtr;
    }

    // Step SPOT automaton
    spotResults = SpotStepper::step(SpotGraph, Registry, ApVarIds, currentState,
                                    Owner, event, C, MainState, FormulaBuilder);
    assert(spotResults.size() <= 1 &&
           "Expected at most one result from SPOT stepping");

    // Update automaton state in GDM with the new state from SPOT stepping
    // Note: SpotStepper::step should update the currentState parameter
    MainState = dsl::setAutomatonState(MainState, event.Symbol, currentState);
  }

  // Step 3: Collect errors and emit them (variant-based handling)
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][HANDLE] Step 3: Processing " << spotResults.size()
                 << " SPOT results\n";
  }
  for (const auto &result : spotResults) {
    handleEventResult(result, C);
  }

  // Step 4: Add transition for the main state
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][HANDLE] Step 4: Adding transition for main state\n";
  }
  C.addTransition(MainState, Pred);
}

// These methods are now implemented as API functions in the dsl namespace
// and can be accessed directly without going through the DSLMonitor class

// (Removed unused DSLMonitor::checkEndAnalysis)

void DSLMonitor::addDeferredLeakReport(const std::string &Message,
                                       const std::string &BugTypeName,
                                       const std::string &BugTypeCategory,
                                       SymbolRef Symbol, ProgramStateRef State,
                                       SourceLocation Location) {
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][DEFERRED] Adding deferred leak report: " << Message
                 << "\n";
  }
  DeferredLeakReports.emplace_back(Message, BugTypeName, BugTypeCategory,
                                   Symbol, State, Location);
}

void DSLMonitor::emitDeferredLeakReports(CheckerContext &C) {
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][DEFERRED] Emitting " << DeferredLeakReports.size()
                 << " deferred leak reports\n";
  }

  for (const auto &report : DeferredLeakReports) {
    static const BugType BT{Owner, report.BugTypeName, report.BugTypeCategory};

    // Create error node using the current CheckerContext's predecessor
    // This ensures we have a valid predecessor node from checkEndFunction
    ExplodedNode *ErrorNode = C.generateErrorNode();
    if (ErrorNode) {
      auto BR = std::make_unique<PathSensitiveBugReport>(BT, report.Message,
                                                         ErrorNode);
      if (report.Symbol)
        BR->markInteresting(report.Symbol);
      C.emitReport(std::move(BR));

      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][DEFERRED] Emitted leak report: "
                     << report.Message
                     << " error_node=" << (const void *)ErrorNode << "\n";
      }
    } else {
      if (edslDebugEnabled()) {
        llvm::errs()
            << "[EDSL][DEFERRED] Failed to create ErrorNode for leak report\n";
      }
    }
  }
}

void DSLMonitor::clearDeferredLeakReports() {
  if (edslDebugEnabled()) {
    llvm::errs() << "[EDSL][DEFERRED] Clearing " << DeferredLeakReports.size()
                 << " deferred leak reports\n";
  }
  DeferredLeakReports.clear();
}
