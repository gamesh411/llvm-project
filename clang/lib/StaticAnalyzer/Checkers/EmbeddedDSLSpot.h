#pragma once

#include "clang/StaticAnalyzer/Checkers/EmbeddedDSLFramework.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

// SPOT forward decls
namespace spot {
class formula;
class twa_graph;
class twa_run;
using twa_graph_ptr = std::shared_ptr<twa_graph>;
} // namespace spot

namespace clang {
namespace ento {
namespace dsl {

// Evaluator for an atomic proposition at a given event/context and a specific
// ProgramState
using APEvaluator = std::function<bool(const GenericEvent &, CheckerContext &,
                                       ProgramStateRef)>;

// Registry mapping DSL Atomic nodes to SPOT AP names and evaluators
class APRegistry {
  std::map<int, std::string> NodeToAP;        // NodeID -> AP name
  std::map<std::string, APEvaluator> APEvals; // AP name -> evaluator

public:
  void registerAP(int nodeId, const std::string &apName, APEvaluator eval) {
    NodeToAP[nodeId] = apName;
    APEvals[apName] = std::move(eval);
  }

  const std::map<int, std::string> &getMapping() const { return NodeToAP; }
  const std::map<std::string, APEvaluator> &getEvaluators() const {
    return APEvals;
  }
};

// Build SPOT items: formula, monitor, registry
struct SpotBuildResult {
  spot::twa_graph_ptr Monitor;
  APRegistry Registry;
};

SpotBuildResult buildSpotMonitorFromDSL(const LTLFormulaBuilder &Builder);

// Unified monitor that encapsulates framework modeling and SPOT stepping
class DSLMonitor {
  // SPOT temporal monitor
  spot::twa_graph_ptr SpotGraph;
  APRegistry Registry;
  // Cache of AP name -> BDD var id to avoid per-step registrations
  std::map<std::string, int> ApVarIds;
  int CurrentState = 0;
  const CheckerBase *Owner; // for diagnostics
  // Inlined pieces of the runtime/framework we need here
  LTLFormulaBuilder FormulaBuilder;
  BindingDrivenEventCreator EventCreator;

public:
  DSLMonitor(spot::twa_graph_ptr M, APRegistry Reg, const CheckerBase *O,
             LTLFormulaBuilder FB)
      : SpotGraph(std::move(M)), Registry(std::move(Reg)), Owner(O),
        FormulaBuilder(std::move(FB)) {
    // Populate binding-driven event creator from the formula
    FormulaBuilder.populateBindingDrivenEventCreator(EventCreator);
  }

  static std::unique_ptr<DSLMonitor>
  create(std::unique_ptr<PropertyDefinition> Property, const CheckerBase *O);

  // Event creation via bindings
  dsl::GenericEvent createBindingDrivenEvent(const CallEvent &Call,
                                             EventType eventType,
                                             CheckerContext &C) const {
    // Re-implement binding-driven event creation locally
    std::string funcName = Call.getCalleeIdentifier()
                               ? Call.getCalleeIdentifier()->getName().str()
                               : "unknown";

    if (EventCreator.hasBindingInfo(funcName)) {
      SymbolRef Sym = nullptr;
      std::string symbolName = "unknown";
      std::string fallbackVarName;
      for (const auto &binding : FormulaBuilder.getSymbolBindings()) {
        if (EventCreator.getBindingType(funcName, binding.SymbolName) !=
            BindingType::Variable) {
          Sym = EventCreator.extractSymbolFromCall(Call, funcName,
                                                   binding.SymbolName);
          if (fallbackVarName.empty())
            fallbackVarName = binding.SymbolName;
          if (Sym) {
            symbolName = binding.SymbolName;
            break;
          }
        }
      }
      if (!Sym) {
        if (eventType == EventType::PostCall) {
          Sym = Call.getReturnValue().getAsSymbol();
          symbolName =
              Sym ? (fallbackVarName.empty()
                         ? ("sym_" + std::to_string(Sym->getSymbolID()))
                         : fallbackVarName)
                  : (fallbackVarName.empty() ? std::string("unknown")
                                             : fallbackVarName);
        } else {
          Sym = nullptr;
          if (Call.getNumArgs() > 0) {
            SVal Arg = Call.getArgSVal(0);
            if (const MemRegion *MR = Arg.getAsRegion()) {
              SVal Stored = C.getState()->getSVal(MR);
              if (SymbolRef StoredSym = Stored.getAsSymbol())
                Sym = StoredSym;
            }
            if (!Sym)
              Sym = Arg.getAsSymbol();
          }
          symbolName =
              Sym ? (fallbackVarName.empty()
                         ? ("sym_" + std::to_string(Sym->getSymbolID()))
                         : fallbackVarName)
                  : (fallbackVarName.empty() ? std::string("unknown")
                                             : fallbackVarName);
        }
      }
      return dsl::GenericEvent(eventType, funcName, symbolName, Sym,
                               Call.getSourceRange().getBegin());
    } else {
      SymbolRef Sym = nullptr;
      std::string symbolName = "unknown";
      if (eventType == EventType::PostCall) {
        Sym = Call.getReturnValue().getAsSymbol();
        symbolName =
            Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
      } else {
        Sym =
            Call.getNumArgs() > 0 ? Call.getArgSVal(0).getAsSymbol() : nullptr;
        symbolName =
            Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
      }
      return dsl::GenericEvent(eventType, funcName, symbolName, Sym,
                               Call.getSourceRange().getBegin());
    }
  }

  // Unified handle: do modeling and SPOT step, emit diag on violation
  void handleEvent(const GenericEvent &event, CheckerContext &C);

  // Safety net reporting at EndAnalysis
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;

  // For tests/introspection
  const LTLFormulaBuilder getFormulaBuilder() const { return FormulaBuilder; }

  // Introspection helpers (read traits from this TU)
  size_t getTrackedCount(ProgramStateRef S) const;
  std::vector<unsigned> getTrackedSymbolIDs(ProgramStateRef S) const;
  std::vector<SymbolRef> getTrackedSymbols(ProgramStateRef S) const;
  bool isTracked(ProgramStateRef S, SymbolRef Sym) const;
  bool isActive(ProgramStateRef S, SymbolRef Sym) const;

  // Query whether the formula uses IsNonNull on a given symbol
  bool shouldSplitOnIsNonNull(const std::string &symbolName) const {
    return isSymbolUsedInIsNonNull(symbolName);
  }

private:
  bool isSymbolUsedInIsNonNull(const std::string &symbolName) const {
    const LTLFormulaNode *root = FormulaBuilder.getRootNode();
    std::function<bool(const LTLFormulaNode *)> dfs =
        [&](const LTLFormulaNode *n) -> bool {
      if (!n)
        return false;
      if (n->Type == LTLNodeType::Atomic) {
        if (n->FunctionName == "__isnonnull" &&
            n->Binding.SymbolName == symbolName)
          return true;
      }
      for (const auto &ch : n->Children)
        if (dfs(ch.get()))
          return true;
      return false;
    };
    return dfs(root);
  }
};

} // namespace dsl
} // namespace ento
} // namespace clang
