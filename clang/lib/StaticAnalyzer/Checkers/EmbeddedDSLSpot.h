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
using twa_graph_ptr = std::shared_ptr<twa_graph>;
} // namespace spot

namespace clang {
namespace ento {
namespace dsl {

// (Removed unused introspection helper declarations)

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
  const CheckerBase *ContainingChecker;
  // SPOT temporal monitor
  spot::twa_graph_ptr SpotGraph;
  APRegistry Registry;
  // Cache of AP name -> BDD var id to avoid per-step registrations
  std::map<std::string, int> ApVarIds;
  const CheckerBase *Owner; // for diagnostics
  // Inlined pieces of the runtime/framework we need here
  LTLFormulaBuilder FormulaBuilder;
  APDrivenEventCreator EventCreator;

  // Deferred error reporting for checkDeadSymbols callbacks
  struct DeferredLeakReport {
    std::string Message;
    std::string BugTypeName;
    std::string BugTypeCategory;
    SymbolRef Symbol;
    ProgramStateRef State;
    SourceLocation Location;

    DeferredLeakReport(const std::string &Msg, const std::string &Type,
                       const std::string &Category, SymbolRef Sym,
                       ProgramStateRef St, SourceLocation Loc)
        : Message(Msg), BugTypeName(Type), BugTypeCategory(Category),
          Symbol(Sym), State(St), Location(Loc) {}
  };

  // Store deferred leak reports to be emitted in
  // checkEndFunction/checkEndAnalysis
  std::vector<DeferredLeakReport> DeferredLeakReports;

public:
  // Event handling result structure

  // Information for deferred bug report creation
  struct NonErrorResult {
    ProgramStateRef State;
    const NoteTag *NoteTag;

    NonErrorResult(ProgramStateRef S, const clang::ento::NoteTag *NT = nullptr)
        : State(S), NoteTag(NT) {}
  };

  struct DeferredErrorResult {
    std::string Message;
    std::string BugTypeName;
    std::string BugTypeCategory;
    SymbolRef Symbol;

    DeferredErrorResult(const std::string &Msg, const std::string &TypeName,
                        const std::string &TypeCategory,
                        SymbolRef Sym = nullptr)
        : Message(Msg), BugTypeName(TypeName), BugTypeCategory(TypeCategory),
          Symbol(Sym) {}
  };

  using EventResult = std::variant<NonErrorResult, DeferredErrorResult>;

private:
  void handleEventResult(const DSLMonitor::EventResult &result,
                         CheckerContext &C);

public:
  DSLMonitor(const CheckerBase *ContainingChecker, spot::twa_graph_ptr M,
             APRegistry Reg, const CheckerBase *O, LTLFormulaBuilder FB)
      : ContainingChecker(ContainingChecker), SpotGraph(std::move(M)),
        Registry(std::move(Reg)), Owner(O), FormulaBuilder(std::move(FB)) {
    // Assert that we always have a valid SpotGraph
    assert(SpotGraph && "SpotGraph must not be null");
    // Populate AP-driven event creator from the formula
    FormulaBuilder.populateAPDrivenEventCreator(EventCreator);

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][BINDINGS] Registered function bindings:\n";
      for (const auto &binding : FormulaBuilder.getSymbolBindings()) {
        llvm::errs() << "  SymbolName='" << binding.SymbolName
                     << "' Type=" << (int)binding.Type << "\n";
      }
      llvm::errs() << "[EDSL][BINDINGS] Function names from formula:\n";
      for (const auto &funcName : FormulaBuilder.getFunctionNames()) {
        llvm::errs() << "  FunctionName='" << funcName << "'\n";
      }
    }
  }

  static std::unique_ptr<DSLMonitor>
  create(std::unique_ptr<PropertyDefinition> Property, const CheckerBase *O);

  // Event creation via bindings
  // Factory helpers for specific events
  dsl::PostCallEvent createPostCallEvent(const CallEvent &Call,
                                         CheckerContext &C) const {
    std::string funcName = Call.getCalleeIdentifier()
                               ? Call.getCalleeIdentifier()->getName().str()
                               : "unknown";
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CREATE] createPostCallEvent: funcName='"
                   << funcName << "'\n";
    }
    const Stmt *origin = Call.getOriginExpr();

    // Find all APs that match this call event
    std::vector<int> matchingAPs = EventCreator.findMatchingAPs(Call, C);

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CREATE] Found " << matchingAPs.size()
                   << " matching APs for funcName='" << funcName << "'\n";
    }

    if (!matchingAPs.empty()) {
      // Use the first matching AP (we can enhance this later to handle
      // multiple)
      int apNodeId = matchingAPs[0];
      std::vector<std::string> symbolNames =
          EventCreator.getSymbolNamesForAP(apNodeId);

      if (edslDebugEnabled()) {
        llvm::errs() << "[EDSL][CREATE] Using AP " << apNodeId
                     << " for event creation\n";
        llvm::errs() << "[EDSL][CREATE] Available symbol names for AP "
                     << apNodeId << ": [";
        for (size_t i = 0; i < symbolNames.size(); ++i) {
          if (i > 0)
            llvm::errs() << ", ";
          llvm::errs() << "'" << symbolNames[i] << "'";
        }
        llvm::errs() << "]\n";
      }

      if (!symbolNames.empty()) {
        std::string symbolName = symbolNames[0]; // Use first symbol name
        SymbolRef Sym =
            EventCreator.extractSymbolFromCall(Call, apNodeId, symbolName);
        BindingType bindingType =
            EventCreator.getBindingType(apNodeId, symbolName);

        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][CREATE] AP-driven extraction: apId="
                       << apNodeId << " symbolName='" << symbolName
                       << "' bindingType=" << (int)bindingType
                       << " Sym=" << (Sym ? "valid" : "null") << "\n";
          llvm::errs()
              << "[EDSL][CREATE] Creating PostCallEvent with symbol ID="
              << (Sym ? Sym->getSymbolID() : 0) << "\n";
        }

        return dsl::PostCallEvent{funcName, symbolName,
                                  Sym,      Call.getSourceRange().getBegin(),
                                  origin,   bindingType};
      }
    }

    // Fallback to default extraction
    SymbolRef Sym = Call.getReturnValue().getAsSymbol();
    std::string symbolName =
        Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
    BindingType d = BindingType::ReturnValue;

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CREATE] Fallback extraction: Sym="
                   << (Sym ? "valid" : "null") << " symbolName='" << symbolName
                   << "'\n";
    }

    return dsl::PostCallEvent{
        funcName, symbolName, Sym, Call.getSourceRange().getBegin(), origin, d};
  }

  dsl::PreCallEvent createPreCallEvent(const CallEvent &Call,
                                       CheckerContext &C) const {
    std::string funcName = Call.getCalleeIdentifier()
                               ? Call.getCalleeIdentifier()->getName().str()
                               : "unknown";
    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CREATE] createPreCallEvent: funcName='"
                   << funcName << "'\n";
    }
    const Stmt *origin = Call.getOriginExpr();

    // Find all APs that match this call event
    std::vector<int> matchingAPs = EventCreator.findMatchingAPs(Call, C);

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CREATE] Found " << matchingAPs.size()
                   << " matching APs for funcName='" << funcName << "'\n";
    }

    if (!matchingAPs.empty()) {
      // Use the first matching AP (we can enhance this later to handle
      // multiple)
      int apNodeId = matchingAPs[0];
      std::vector<std::string> symbolNames =
          EventCreator.getSymbolNamesForAP(apNodeId);

      if (!symbolNames.empty()) {
        std::string symbolName = symbolNames[0]; // Use first symbol name
        SymbolRef Sym =
            EventCreator.extractSymbolFromCall(Call, apNodeId, symbolName);
        BindingType bindingType =
            EventCreator.getBindingType(apNodeId, symbolName);

        if (edslDebugEnabled()) {
          llvm::errs() << "[EDSL][CREATE] AP-driven extraction: apId="
                       << apNodeId << " symbolName='" << symbolName
                       << "' bindingType=" << (int)bindingType
                       << " Sym=" << (Sym ? "valid" : "null") << "\n";
        }

        return dsl::PreCallEvent{funcName, symbolName,
                                 Sym,      Call.getSourceRange().getBegin(),
                                 origin,   bindingType};
      }
    }

    // Fallback to default extraction
    SymbolRef Sym =
        Call.getNumArgs() > 0 ? Call.getArgSVal(0).getAsSymbol() : nullptr;
    std::string symbolName =
        Sym ? "sym_" + std::to_string(Sym->getSymbolID()) : "unknown";
    BindingType d = BindingType::FirstParameter;

    if (edslDebugEnabled()) {
      llvm::errs() << "[EDSL][CREATE] Fallback extraction: Sym="
                   << (Sym ? "valid" : "null") << " symbolName='" << symbolName
                   << "'\n";
    }

    return dsl::PreCallEvent{
        funcName, symbolName, Sym, Call.getSourceRange().getBegin(), origin, d};
  }

  // Overloads for specific event types

  // Main event handler - processes events and manages state transitions
  void handleEvent(const GenericEvent &event, CheckerContext &C);
  // Bridging overloads for specific event structs
  void handleEvent(const PostCallEvent &event, CheckerContext &C);
  void handleEvent(const PreCallEvent &event, CheckerContext &C);
  void handleEvent(const DeadSymbolsEvent &event, CheckerContext &C);
  void handleEvent(const EndFunctionEvent &event, CheckerContext &C);
  void handleEvent(const EndAnalysisEvent &event, CheckerContext &C);
  void handleEvent(const PointerEscapeEvent &event, CheckerContext &C);
  void handleEvent(const BindEvent &event, CheckerContext &C);

  // Safety net reporting at EndAnalysis
  // (Removed unused checkEndAnalysis)

  // Deferred leak report management
  void addDeferredLeakReport(const std::string &Message,
                             const std::string &BugTypeName,
                             const std::string &BugTypeCategory,
                             SymbolRef Symbol, ProgramStateRef State,
                             SourceLocation Location);
  void emitDeferredLeakReports(CheckerContext &C);
  void clearDeferredLeakReports();

  // For tests/introspection
  const LTLFormulaBuilder getFormulaBuilder() const { return FormulaBuilder; }

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
        if (n->Binding.SymbolName == symbolName &&
            isNonNullBinding(n->Binding.Type))
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
