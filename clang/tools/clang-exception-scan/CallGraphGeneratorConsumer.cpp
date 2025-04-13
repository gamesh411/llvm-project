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
  llvm::errs() << "\n=== Starting addCall ===\n";
  if (!Caller || !Callee) {
    llvm::errs() << "Failed to add call - null pointer:\n"
                 << "Caller: "
                 << (Caller ? Caller->getNameAsString() : "<nullptr>") << "\n"
                 << "Callee: "
                 << (Callee ? Callee->getNameAsString() : "<nullptr>") << "\n";
    return;
  }

  assert(Caller->isThisDeclarationADefinition() &&
         "Caller must be a definition");

  std::optional<std::string> CallerUSR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Caller);
  std::optional<std::string> CalleeUSR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Callee);

  llvm::errs() << "Call details:\n"
               << "- Caller name: " << Caller->getNameAsString() << "\n"
               << "- Callee name: " << Callee->getNameAsString() << "\n"
               << "- Current TU: " << CurrentTU_ << "\n"
               << "- Caller USR: " << (CallerUSR ? *CallerUSR : "<failed>")
               << "\n"
               << "- Callee USR: " << (CalleeUSR ? *CalleeUSR : "<failed>")
               << "\n";

  if (!CallerUSR || !CalleeUSR) {
    llvm::errs() << "Failed to generate USR for caller or callee\n";
    return;
  }

  // Store the call dependency
  const SourceManager &SM = Context_.getSourceManager();
  CallDependency CD;
  CD.CallerUSR = *CallerUSR;
  CD.CalleeUSR = *CalleeUSR;
  CD.CallLocFile = SM.getBufferName(E->getBeginLoc());
  CD.CallLocLine = SM.getSpellingLineNumber(E->getBeginLoc());
  CD.CallLocColumn = SM.getSpellingColumnNumber(E->getBeginLoc());

  llvm::errs() << "Call location:\n"
               << "- File: " << CD.CallLocFile << "\n"
               << "- Line: " << CD.CallLocLine << "\n"
               << "- Column: " << CD.CallLocColumn << "\n";

  {
    std::lock_guard<std::mutex> Lock(GCG_.CallDependenciesMutex);
    GCG_.CallDependencies.push_back(CD);
    llvm::errs() << "Added call dependency (total: "
                 << GCG_.CallDependencies.size() << ")\n";
  }

  // Add the caller and callee to the TU to USR map
  {
    std::lock_guard<std::mutex> Lock(GCG_.TUToUSRMapMutex);
    GCG_.TUToUSRMap[CurrentTU_].insert(*CallerUSR);
    llvm::errs() << "Added caller USR to TUToUSRMap for TU: " << CurrentTU_
                 << "\n";
  }

  // Add the TU dependency if the callee is defined in a different TU
  auto CalleeTU = GCG_.USRToDefinedInTUMap.find(*CalleeUSR);
  if (CalleeTU != GCG_.USRToDefinedInTUMap.end()) {
    llvm::errs() << "Found callee TU: " << CalleeTU->second << "\n";
    if (CalleeTU->second != CurrentTU_) {
      std::lock_guard<std::mutex> Lock(GCG_.TUDependenciesMutex);
      GCG_.TUDependencies.push_back({CurrentTU_, CalleeTU->second});
      llvm::errs() << "Added TU dependency: " << CurrentTU_ << " -> "
                   << CalleeTU->second << "\n";
    } else {
      llvm::errs() << "Skipping TU dependency (same TU)\n";
    }
  } else {
    llvm::errs() << "Callee TU not found in USRToDefinedInTUMap\n";
  }

  llvm::errs() << "=== Finished addCall ===\n\n";
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

bool CallGraphVisitor::VisitLambdaExpr(LambdaExpr *Lambda) {
  // First, track the lambda's call operator as the current function
  if (const CXXMethodDecl *CallOperator = Lambda->getCallOperator()) {
    // Register the lambda's call operator in the USRToDefinedInTUMap
    if (std::optional<std::string> CallOperatorUSR =
            cross_tu::CrossTranslationUnitContext::getLookupName(
                CallOperator)) {
      std::lock_guard<std::mutex> Lock(GCG_.USRToDefinedInTUMapMutex);
      GCG_.USRToDefinedInTUMap[*CallOperatorUSR] = CurrentTU_;

      // Also add it to the USRToFunctionMap
      FunctionMappingInfo Info;
      Info.USR = *CallOperatorUSR;
      Info.TU = CurrentTU_;
      Info.FunctionName = CallOperator->getNameAsString();
      Info.Loc = CallOperator->getLocation();
      Info.IsDefinition = true; // Lambda call operators are always definitions
      {
        std::lock_guard<std::mutex> Lock(GCG_.USRToFunctionMapMutex);
        GCG_.USRToFunctionMap[*CallOperatorUSR] = Info;
      }
    }

    // Store the previous current function
    const FunctionDecl *PreviousFunction = CurrentFunction_;

    // Set the current function to the lambda's call operator
    CurrentFunction_ = CallOperator;

    // Add the lambda's body to the call graph
    if (Stmt *Body = CallOperator->getBody()) {
      TraverseStmt(Body);
    }

    // Restore the previous current function
    CurrentFunction_ = PreviousFunction;
  }
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
    llvm::errs() << "Inserting TU: " << CurrentTU << "\n";
    std::lock_guard<std::mutex> Lock(GCG_.TUsMutex);
    GCG_.TUs.insert(CurrentTU);
  }

  // First, use USRMappingConsumer to collect function definitions
  USRMappingConsumer USRConsumer(CurrentTU, GCG_);
  USRConsumer.HandleTranslationUnit(Context);

  // Then, use CallGraphVisitor to collect function calls
  CallGraphVisitor Visitor(Context, GCG_, CurrentTU);
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());
}

// Helper function for cycle detection using DFS
static bool
hasCycleDFS(const std::string &TU,
            const std::map<std::string, std::set<std::string>> &Graph,
            std::unordered_set<std::string> &Visited,
            std::unordered_set<std::string> &RecStack,
            std::vector<std::string> &Path,
            std::vector<std::vector<std::string>> &Cycles) {

  llvm::errs() << "DFS visiting: " << TU << "\n";
  llvm::errs() << "Current path: ";
  for (const auto &Node : Path) {
    llvm::errs() << Node << " -> ";
  }
  llvm::errs() << "\n";

  Visited.insert(TU);
  RecStack.insert(TU);
  Path.push_back(TU);

  bool HasCycle = false;
  for (const auto &Neighbor : Graph.at(TU)) {
    llvm::errs() << "Checking neighbor " << Neighbor << " of " << TU << "\n";
    if (RecStack.find(Neighbor) != RecStack.end()) {
      // Found a cycle, add the current path to the result
      auto It = std::find(Path.begin(), Path.end(), Neighbor);
      if (It != Path.end()) {
        std::vector<std::string> Cycle(It, Path.end());
        Cycle.push_back(Neighbor); // Close the cycle
        Cycles.push_back(Cycle);
        HasCycle = true;
        llvm::errs() << "Found cycle: ";
        for (const auto &Node : Cycle) {
          llvm::errs() << Node << " -> ";
        }
        llvm::errs() << "\n";
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

  llvm::errs() << "DEBUG: Building TU dependency graph from "
               << GCG.CallDependencies.size() << " call dependencies\n";

  // Debug print all call dependencies
  for (const auto &CD : GCG.CallDependencies) {
    llvm::errs() << "DEBUG: Call dependency - Caller USR: " << CD.CallerUSR
                 << ", Callee USR: " << CD.CalleeUSR << "\n";
  }

  // Debug print TU dependencies
  llvm::errs() << "DEBUG: TU Dependencies:\n";
  for (const auto &Dep : TUDeps) {
    llvm::errs() << "DEBUG: " << Dep.first << " -> ";
    for (const auto &Target : Dep.second) {
      llvm::errs() << Target << " ";
    }
    llvm::errs() << "\n";
  }

  // Initialize with all TUs
  llvm::errs() << "All TUs:\n";
  for (const auto &TU : GCG.TUs) {
    llvm::errs() << "  " << TU << "\n";
    if (TUDeps.find(TU) == TUDeps.end()) {
      TUDeps[TU] = std::set<std::string>();
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

  // Debug output
  llvm::errs() << "Found " << Cycles.size() << " cycles\n";
  for (const auto &Cycle : Cycles) {
    llvm::errs() << "Cycle: ";
    for (const auto &TU : Cycle) {
      llvm::errs() << TU << " -> ";
    }
    llvm::errs() << "\n";
  }

  return Cycles;
}

namespace clang::exception_scan {

// Build a translation unit dependency graph from call dependencies
std::map<std::string, std::set<std::string>>
buildTUDependencyGraph(const GlobalExceptionInfo &GCG) {
  std::map<std::string, std::set<std::string>> TUDependencies;

  // Debug output for initial state
  llvm::errs() << "\n=== Starting buildTUDependencyGraph ===\n";
  llvm::errs() << "Initial state:\n";
  llvm::errs() << "- Number of call dependencies: "
               << GCG.CallDependencies.size() << "\n";
  llvm::errs() << "- Number of functions in USRToFunctionMap: "
               << GCG.USRToFunctionMap.size() << "\n";
  llvm::errs() << "- Number of TUs in USRToDefinedInTUMap: "
               << GCG.USRToDefinedInTUMap.size() << "\n\n";

  // First, add all TUs to the dependency map to ensure they're all represented
  llvm::errs() << "Found TUs:\n";
  for (const auto &TU : GCG.TUs) {
    TUDependencies[TU] = std::set<std::string>();
    llvm::errs() << "- " << TU << "\n";
  }
  llvm::errs() << "\n";

  // Debug output for function definitions
  llvm::errs() << "Function definitions in USRToFunctionMap:\n";
  for (const auto &Entry : GCG.USRToFunctionMap) {
    llvm::errs() << "- USR: " << Entry.first << "\n"
                 << "  Name: " << Entry.second.FunctionName << "\n"
                 << "  TU: " << Entry.second.TU << "\n"
                 << "  IsDefinition: " << Entry.second.IsDefinition << "\n";
  }
  llvm::errs() << "\n";

  // Debug output for TU definitions
  llvm::errs() << "TU definitions in USRToDefinedInTUMap:\n";
  for (const auto &Entry : GCG.USRToDefinedInTUMap) {
    llvm::errs() << "- USR: " << Entry.first << "\n"
                 << "  TU: " << Entry.second << "\n";
  }
  llvm::errs() << "\n";

  // Process all call dependencies
  llvm::errs() << "Processing call dependencies:\n";
  for (const auto &Call : GCG.CallDependencies) {
    llvm::errs() << "\nAnalyzing call:\n"
                 << "- Caller USR: " << Call.CallerUSR << "\n"
                 << "- Callee USR: " << Call.CalleeUSR << "\n";

    auto CallerIt = GCG.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeDefTU = GCG.USRToDefinedInTUMap.find(Call.CalleeUSR);

    if (CallerIt != GCG.USRToFunctionMap.end()) {
      llvm::errs() << "Found caller in USRToFunctionMap:\n"
                   << "- Name: " << CallerIt->second.FunctionName << "\n"
                   << "- TU: " << CallerIt->second.TU << "\n";
    } else {
      llvm::errs() << "WARNING: Caller USR not found in USRToFunctionMap\n";
    }

    if (CalleeDefTU != GCG.USRToDefinedInTUMap.end()) {
      llvm::errs() << "Found callee TU in USRToDefinedInTUMap: "
                   << CalleeDefTU->second << "\n";
    } else {
      llvm::errs() << "WARNING: Callee USR not found in USRToDefinedInTUMap\n";
    }

    if (CallerIt != GCG.USRToFunctionMap.end() &&
        CalleeDefTU != GCG.USRToDefinedInTUMap.end()) {
      // Skip self-dependencies
      if (CallerIt->second.TU == CalleeDefTU->second) {
        llvm::errs() << "Skipping self-dependency in " << CallerIt->second.TU
                     << "\n";
        continue;
      }

      llvm::errs() << "Adding dependency: " << CallerIt->second.TU << " -> "
                   << CalleeDefTU->second << "\n";

      // Add the callee's TU to the caller's dependencies
      TUDependencies[CallerIt->second.TU].insert(CalleeDefTU->second);

      // Also ensure the callee's TU exists in the map
      if (TUDependencies.find(CalleeDefTU->second) == TUDependencies.end()) {
        TUDependencies[CalleeDefTU->second] = std::set<std::string>();
        llvm::errs() << "Added empty dependency set for TU: "
                     << CalleeDefTU->second << "\n";
      }
    }
  }

  // Debug output final TU dependency graph
  llvm::errs() << "\nFinal TU Dependency Graph:\n";
  for (const auto &Entry : TUDependencies) {
    llvm::errs() << "TU: " << Entry.first << "\n";
    llvm::errs() << "Dependencies:\n";
    for (const auto &Dep : Entry.second) {
      llvm::errs() << "  -> " << Dep << "\n";
    }
  }
  llvm::errs() << "\n=== Finished buildTUDependencyGraph ===\n\n";

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
    llvm::errs() << "Failed to open output file: " << OutputPath << "\n";
    return;
  }

  // Write DOT header
  OutFile << "digraph TUDependencies {\n";
  OutFile << "  rankdir=LR;\n";
  OutFile << "  node [shape=box, style=filled, fillcolor=lightblue];\n\n";

  // Get all TUs and build the dependency graph
  auto Graph = buildTUDependencyGraph(GCG);

  // Write nodes
  for (const auto &TU : GCG.TUs) {
    // Extract just the filename from the path
    std::string ShortName = TU;
    size_t LastSlash = ShortName.find_last_of("/\\");
    if (LastSlash != std::string::npos) {
      ShortName = ShortName.substr(LastSlash + 1);
    }

    OutFile << "  \"" << TU << "\" [label=\"" << ShortName << "\"];\n";
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