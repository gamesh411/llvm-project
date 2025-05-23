#include "CallGraphGeneratorConsumer.h"
#include "USRMappingConsumer.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/SourceManager.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/Support/GraphWriter.h"

#include <algorithm>
#include <fstream>
#include <optional>
#include <unordered_map>
#include <unordered_set>

using namespace clang;
using namespace clang::exception_scan;

void CallGraphVisitor::addCall(const FunctionDecl *Caller,
                               const FunctionDecl *Callee, const Expr *E) {
  // TODO: Implement a proper logging system with log levels to reduce the
  // noise, and eliminate this hack. We filter for isInMainFile to reduce the
  // noise.
  const SourceManager &SM = Context_.getSourceManager();

  if (!Caller || !Callee) {
    return;
  }

  std::optional<std::string> CallerUSR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Caller);
  std::optional<std::string> CalleeUSR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Callee);

  if (!CallerUSR || !CalleeUSR) {
    return;
  }

  // Store the call dependency
  CallDependency CD;
  CD.CallerUSR = *CallerUSR;
  CD.CalleeUSR = *CalleeUSR;
  CD.CallLocFile = SM.getBufferName(E->getBeginLoc());
  CD.CallLocLine = SM.getSpellingLineNumber(E->getBeginLoc());
  CD.CallLocColumn = SM.getSpellingColumnNumber(E->getBeginLoc());

  {
    std::lock_guard<std::mutex> Lock(GCG_.CallDependenciesMutex);
    const auto Result = GCG_.CallDependencies.insert(CD);
    if (Result.second) {
      ChangesMade_ = true;
    }
  }

  // This is not needed if we presuppose the USRMappingConsumer has already
  // added the caller USR to the TUToUSRMap
  //
  // NOTE: If we were to merge the USRMappingConsumer and
  // CallGraphGeneratorConsumer, we could add the caller USR to the TUToUSRMap
  // here with an implementation like this:
  //
  // {
  // std::lock_guard<std::mutex> Lock(GCG_.TUToUSRMapMutex);
  // const auto Result = GCG_.TUToUSRMap[CurrentTU_].insert(*CallerUSR);
  // if (Result.second) {
  //   ChangesMade_ = true;
  // }
  // }

  // Add the TU dependency if the callee is defined in a different TU
  // We do not track dependencies for system headers, as they lead to false
  // dependencies between TUs.
  if (SM.isInSystemHeader(Callee->getBeginLoc())) {
    return;
  }
  // NOTE: We only read from USRToDefinedInTUMap, so we don't need to lock if
  // this stage (CallGraphGeneration) is the only one that reads from it.
  // TODO: If the above is really true, optimize by not locking.
  std::lock_guard<std::mutex> Lock(GCG_.USRToDefinedInTUMapMutex);
  auto CalleeTU = GCG_.USRToDefinedInTUMap.find(*CalleeUSR);
  if (CalleeTU != GCG_.USRToDefinedInTUMap.end()) {
    // TODO: From the build system, we could narrow the set of potential TUs
    // that are linked together with the current TU. For now, we use all TUs
    // that have a function definition for the callee.
    for (const auto &DefiningTUEntry : CalleeTU->getValue()) {
      const StringRef DefiningTU = DefiningTUEntry.getKey();
      if (DefiningTU != CurrentTU_) {
        // Add the dependency to the TUDependencyGraph
        const auto &Result =
            GCG_.TUDependencies.addDependency(CurrentTU_, DefiningTU.str());
        if (Result) {
          ChangesMade_ = true;
        }
      }
    }
  }
}

bool CallGraphVisitor::VisitCallExpr(CallExpr *Call) {
  if (const FunctionDecl *Callee = Call->getDirectCallee()) {
    // Handle template function calls
    if (const FunctionTemplateSpecializationInfo *TemplateInfo =
            Callee->getTemplateSpecializationInfo()) {
      // Get the template declaration
      const FunctionTemplateDecl *TemplateDecl = TemplateInfo->getTemplate();
      if (TemplateDecl) {
        // Get the templated function
        const FunctionDecl *TemplatedFunc = TemplateDecl->getTemplatedDecl();
        addCall(CurrentFunction_, TemplatedFunc, Call);
      }
    }
    // Always add the direct call as well
    addCall(CurrentFunction_, Callee, Call);
  }
  return true;
}

bool CallGraphVisitor::VisitCXXConstructExpr(CXXConstructExpr *Construct) {
  if (const CXXConstructorDecl *Ctor = Construct->getConstructor()) {
    addCall(CurrentFunction_, Ctor, Construct);
  }
  return true;
}

bool CallGraphVisitor::VisitCXXNewExpr(CXXNewExpr *New) {
  if (const FunctionDecl *Allocator = New->getOperatorNew()) {
    addCall(CurrentFunction_, Allocator, New);
  }
  return true;
}

bool CallGraphVisitor::VisitCXXDeleteExpr(CXXDeleteExpr *Delete) {
  if (const FunctionDecl *Deallocator = Delete->getOperatorDelete()) {
    addCall(CurrentFunction_, Deallocator, Delete);
  }
  return true;
}

bool CallGraphVisitor::VisitFunctionDecl(FunctionDecl *FD) {
  if (!FD->isThisDeclarationADefinition())
    return true;

  CurrentFunction_ = FD;
  return true;
}

bool CallGraphVisitor::VisitCXXMethodDecl(CXXMethodDecl *MD) {
  // We want to track both definitions and declarations for virtual functions
  CurrentFunction_ = MD;
  return true;
}

bool CallGraphVisitor::VisitCXXOperatorCallExpr(CXXOperatorCallExpr *Call) {
  if (const FunctionDecl *Callee = Call->getDirectCallee()) {
    // Handle operator() calls, which could be lambda invocations
    if (const CXXMethodDecl *Method = dyn_cast<CXXMethodDecl>(Callee)) {
      if (Method->getParent()->isLambda()) {
        addCall(CurrentFunction_, Method, Call);
      }
    }
  }
  return true;
}

void CallGraphGeneratorConsumer::HandleTranslationUnit(ASTContext &Context) {
  std::string CurrentTU = "<unknown>";
  if (const SourceManager *SM = &Context.getSourceManager()) {
    if (const FileEntry *FE = SM->getFileEntryForID(SM->getMainFileID())) {
      CurrentTU = FE->tryGetRealPathName().str();
    }
  }

  {
    std::lock_guard<std::mutex> Lock(GCG_.TUsMutex);
    const auto Result = GCG_.TUs.insert(CurrentTU);
    if (Result.second) {
      ChangedFlag_.store(true, std::memory_order_relaxed);
    }
  }

  GCG_.TUDependencies.addIndependentTU(CurrentTU);

  CallGraphVisitor Visitor(Context, GCG_, CurrentTU);
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());

  if (Visitor.hasMadeChanges()) {
    ChangedFlag_.store(true, std::memory_order_relaxed);
  }
}

// Helper function for cycle detection using DFS
static bool
hasCycleDFS(const std::string &TU,
            const std::map<std::string, std::set<std::string>> &Graph,
            std::unordered_set<std::string> &Visited,
            std::unordered_set<std::string> &RecStack,
            std::vector<std::string> &Path,
            std::vector<std::vector<std::string>> &Cycles) {

  Visited.insert(TU);
  RecStack.insert(TU);
  Path.push_back(TU);

  bool HasCycle = false;
  for (const auto &Neighbor : Graph.at(TU)) {
    if (RecStack.find(Neighbor) != RecStack.end()) {
      // Found a cycle, add the current path to the result
      auto It = std::find(Path.begin(), Path.end(), Neighbor);
      if (It != Path.end()) {
        std::vector<std::string> Cycle(It, Path.end());
        Cycle.push_back(Neighbor); // Close the cycle
        Cycles.push_back(Cycle);
        HasCycle = true;
      }
    } else if (Visited.find(Neighbor) == Visited.end()) {
      HasCycle |= hasCycleDFS(Neighbor, Graph, Visited, RecStack, Path, Cycles);
    }
  }

  RecStack.erase(TU);
  Path.pop_back();
  return HasCycle;
}

std::vector<std::vector<std::string>>
clang::exception_scan::detectTUCycles(const GlobalExceptionInfo &GCG) {
  std::vector<std::vector<std::string>> Cycles;
  std::map<std::string, std::set<std::string>> TUDeps =
      buildTUDependencyGraph(GCG);

  // Initialize with all TUs
  for (const auto &[TU, _] : GCG.TUs) {
    if (TUDeps.find(TU.str()) == TUDeps.end()) {
      TUDeps[TU.str()] = {};
    }
  }

  std::unordered_set<std::string> Visited;
  std::unordered_set<std::string> RecStack;
  std::vector<std::string> Path;

  for (const auto &TU : TUDeps) {
    if (Visited.find(TU.first) == Visited.end()) {
      Path.clear();
      hasCycleDFS(TU.first, TUDeps, Visited, RecStack, Path, Cycles);
    }
  }

  return Cycles;
}

namespace clang::exception_scan {

// Build a translation unit dependency graph from call dependencies
std::map<std::string, std::set<std::string>>
buildTUDependencyGraph(const GlobalExceptionInfo &GCG) {
  std::map<std::string, std::set<std::string>> TUDependencies;

  // First, add all TUs to the dependency map to ensure they're all represented
  for (const auto &[TU, _] : GCG.TUs) {
    TUDependencies[TU.str()] = std::set<std::string>();
  }

  // Process all call dependencies
  for (const auto &Call : GCG.CallDependencies) {
    auto CallerIt = GCG.USRToFunctionMap.find(Call.CallerUSR);
    if (CallerIt != GCG.USRToFunctionMap.end()) {
    }

    auto CalleeDefTU = GCG.USRToDefinedInTUMap.find(Call.CalleeUSR);
    if (CallerIt != GCG.USRToFunctionMap.end() &&
        CalleeDefTU != GCG.USRToDefinedInTUMap.end()) {
      const auto &CallerTU = CallerIt->getValue().TU;
      const auto &CalleeDefTUValue = CalleeDefTU->getValue();
      for (const auto &[CalleeTU, _] : CalleeDefTUValue) {
        // Skip self-dependencies
        if (CallerTU == CalleeTU) {
          continue;
        }
        // Add the callee's TU to the caller's dependencies
        TUDependencies[CallerTU.str().str()].emplace(CalleeTU.str());
      }
    }
  }

  return TUDependencies;
}

void computeTransitiveClosure(
    std::map<std::string, std::set<std::string>> &TUDependencies) {
  // For each TU in the graph
  for (const auto &[TU, Dependencies] : TUDependencies) {
    // For each direct dependency of this TU
    for (const auto &DirectDep : Dependencies) {
      // For each dependency of the direct dependency
      auto It = TUDependencies.find(DirectDep);
      if (It != TUDependencies.end()) {
        // Add all transitive dependencies
        TUDependencies[TU].insert(It->second.begin(), It->second.end());
      }
    }
  }
}

} // namespace clang::exception_scan

// Implementation of the exported function
void clang::exception_scan::generateDependencyDotFile(
    const GlobalExceptionInfo &GCG, const std::string &OutputPath) {
  std::ofstream OutFile(OutputPath);
  if (!OutFile) {
    return;
  }

  // Write DOT header
  OutFile << "digraph TUDependencies {\n";
  OutFile << "  rankdir=LR;\n";
  OutFile << "  node [shape=box, style=filled, fillcolor=lightblue];\n\n";

  // Get all TUs and build the dependency graph
  auto Graph = buildTUDependencyGraph(GCG);

  // Write nodes
  for (const auto &[TU, _] : GCG.TUs) {
    // Extract just the filename from the path
    std::string ShortName = TU.str();
    size_t LastSlash = ShortName.find_last_of("/\\");
    if (LastSlash != std::string::npos) {
      ShortName = ShortName.substr(LastSlash + 1);
    }

    OutFile << "  \"" << TU.str() << "\" [label=\"" << ShortName << "\"];\n";
  }

  OutFile << "\n";

  // Write edges
  for (const auto &TU : Graph) {
    for (const auto &Dependency : TU.second) {
      OutFile << "  \"" << TU.first << "\" -> \"" << Dependency << "\";\n";
    }
  }

  // Write footer
  OutFile << "}\n";

  OutFile.close();
}
