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
}

namespace clang {
namespace ento {
namespace dsl {

// Evaluator for an atomic proposition at a given event/context
using APEvaluator = std::function<bool(const GenericEvent &, CheckerContext &)>;

// Registry mapping DSL Atomic nodes to SPOT AP names and evaluators
class APRegistry {
  std::map<int, std::string> NodeToAP; // NodeID -> AP name
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
  std::unique_ptr<MonitorAutomaton> Runtime; // framework modeling/runtime
  // SPOT temporal monitor
  spot::twa_graph_ptr SpotGraph;
  APRegistry Registry;
  // Cache of AP name -> BDD var id to avoid per-step registrations
  std::map<std::string, int> ApVarIds;
  int CurrentState = 0;
  const CheckerBase *Owner;                  // for diagnostics

public:
  DSLMonitor(std::unique_ptr<MonitorAutomaton> R,
             spot::twa_graph_ptr M,
             APRegistry Reg,
             const CheckerBase *O)
      : Runtime(std::move(R)), SpotGraph(std::move(M)), Registry(std::move(Reg)), Owner(O) {}

  static std::unique_ptr<DSLMonitor>
  create(std::unique_ptr<PropertyDefinition> Property, const CheckerBase *O);

  // Event creation via bindings
  dsl::GenericEvent createBindingDrivenEvent(const CallEvent &Call,
                                             EventType eventType,
                                             CheckerContext &C) const {
    return Runtime->createBindingDrivenEvent(Call, eventType, C);
  }

  // Unified handle: do modeling and SPOT step, emit diag on violation
  void handleEvent(const GenericEvent &event, CheckerContext &C);

  // Safety net reporting at EndAnalysis
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

  // For tests/introspection
  const LTLFormulaBuilder getFormulaBuilder() const { return Runtime->getFormulaBuilder(); }
};

} // namespace dsl
} // namespace ento
} // namespace clang


