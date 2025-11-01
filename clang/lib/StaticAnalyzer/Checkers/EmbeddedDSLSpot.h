#pragma once

#include <bddx.h>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "clang/StaticAnalyzer/Checkers/EmbeddedDSLFramework.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "spot/twa/fwd.hh"
namespace clang { namespace ento { class CallEvent; } }
namespace clang { namespace ento { class CheckerBase; } }
namespace clang { namespace ento { class CheckerContext; } }

namespace clang::ento::dsl {

// Type aliases for readability
using AutomatonStateID = int;
using AtomicPropositionID = int;
using BindingVarID = std::string;
using FormulaNodeID = int;

ProgramStateRef setAutomatonStateForSymbol(ProgramStateRef State, SymbolRef Sym,
                                           AutomatonStateID StateValue);
const AutomatonStateID *getAutomatonStateForSymbol(ProgramStateRef State,
                                                   SymbolRef Sym);
ProgramStateRef removeAutomatonStateForSymbol(ProgramStateRef State,
                                              SymbolRef Sym);

// TODO: remove this and make this a non-GDM mapping inside the Monitor
// ProgramStateRef setFormulaNodeForAtomicProposition(ProgramStateRef State,
//                                                    AtomicPropositionID APID,
//                                                    FormulaNodeID NodeID);
// const FormulaNodeID *
// getFormulaNodeForAtomicProposition(ProgramStateRef State,
//                                    AtomicPropositionID APID);
// ProgramStateRef removeFormulaNodeForAtomicProposition(ProgramStateRef State,
//                                                       AtomicPropositionID
//                                                       APID);
// END TODO

ProgramStateRef setBindingVarForSymbol(ProgramStateRef State, SymbolRef Sym,
                                       BindingVarID VarID);
const BindingVarID *getBindingVarForSymbol(ProgramStateRef State,
                                           SymbolRef Sym);
ProgramStateRef removeBindingVarForSymbol(ProgramStateRef State, SymbolRef Sym);

struct PostCallEvent {
  const CallEvent &Call;
  CheckerContext &C;
};

struct PreCallEvent {
  const CallEvent &Call;
  CheckerContext &C;
};

struct DeadSymbolsEvent {
  std::function<bool(SymbolRef)> IsSymbolDead;
  CheckerContext &C;
};

struct EndAnalysisEvent {};

// Generic Property Implementation
struct PropertyDefinition {
  LTLFormula Formula;
  std::string PropertyName;
  std::string FormulaString;

  PropertyDefinition(const std::string &name, const std::string &formulaStr,
                     std::shared_ptr<LTLFormulaNode> formula)
      : PropertyName(name), FormulaString(formulaStr) {
    Formula.setFormula(formula);
  }
};

class DSLMonitor {
  const CheckerBase *ContainingChecker;
  std::unique_ptr<PropertyDefinition> Property;

  spot::twa_graph_ptr SpotGraph;

  std::map<FormulaNodeID, AtomicPropositionID> AtomicPropositionForFormulaNode;
  std::map<AtomicPropositionID, FormulaNodeID> FormulaNodeForAtomicProposition;
  std::map<FormulaNodeID, std::optional<BindingVarID>> BindingVarForFormulaNode;
  std::map<BindingVarID, std::vector<FormulaNodeID>> FormulaNodesForBindingVar;
  std::map<AtomicPropositionID, bdd> BDDForAtomicProposition;

public:
  DSLMonitor(const CheckerBase *ContainingChecker,
             std::unique_ptr<PropertyDefinition> Property);

  // Event handlers for available event types
  void handleEvent(PostCallEvent event);
  void handleEvent(PreCallEvent event);
  void handleEvent(DeadSymbolsEvent event);
  void handleEvent(EndAnalysisEvent event);
};
} // namespace clang::ento::dsl