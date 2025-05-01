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
  // noise, and eliminate this hack.
  const SourceManager &SM = Context_.getSourceManager();
  const bool IsCallerInMainFile = SM.isInMainFile(Caller->getOuterLocStart());
  const bool IsCalleeInMainFile = SM.isInMainFile(Callee->getOuterLocStart());
  auto &LOG =
      IsCallerInMainFile || IsCalleeInMainFile ? llvm::errs() : llvm::nulls();

  LOG << "\n=== Starting addCall ===\n";
  if (!Caller || !Callee) {
    LOG << "Failed to add call - null pointer:\n"
        << "Caller: " << (Caller ? Caller->getNameAsString() : "<nullptr>")
        << "\n"
        << "Callee: " << (Callee ? Callee->getNameAsString() : "<nullptr>")
        << "\n";
    return;
  }

  if (!Caller->isThisDeclarationADefinition()) {
    LOG << "Caller is a declaration\n";
  }

  std::optional<std::string> CallerUSR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Caller);
  std::optional<std::string> CalleeUSR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Callee);

  LOG << "Call details:\n"
      << "- Caller name: " << Caller->getNameAsString() << "\n"
      << "- Callee name: " << Callee->getNameAsString() << "\n"
      << "- Current TU: " << CurrentTU_ << "\n"
      << "- Caller USR: " << (CallerUSR ? *CallerUSR : "<failed>") << "\n"
      << "- Callee USR: " << (CalleeUSR ? *CalleeUSR : "<failed>") << "\n";

  if (!CallerUSR || !CalleeUSR) {
    LOG << "Failed to generate USR for caller or callee\n";
    return;
  }

  // Store the call dependency
  CallDependency CD;
  CD.CallerUSR = *CallerUSR;
  CD.CalleeUSR = *CalleeUSR;
  CD.CallLocFile = SM.getBufferName(E->getBeginLoc());
  CD.CallLocLine = SM.getSpellingLineNumber(E->getBeginLoc());
  CD.CallLocColumn = SM.getSpellingColumnNumber(E->getBeginLoc());

  LOG << "Call location:\n"
      << "- File: " << CD.CallLocFile << "\n"
      << "- Line: " << CD.CallLocLine << "\n"
      << "- Column: " << CD.CallLocColumn << "\n";

  {
    std::lock_guard<std::mutex> Lock(GCG_.CallDependenciesMutex);
    const auto Result = GCG_.CallDependencies.insert(CD);
    if (Result.second) {
      LOG << "Added call dependency (total: " << GCG_.CallDependencies.size()
          << ")\n";
      ChangesMade_ = true;
    } else {
      LOG << "Skipping already added call dependency\n";
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
  //   llvm::errs() << "Added caller USR to TUToUSRMap for TU: " << CurrentTU_
  //   << "\n"; ChangesMade_ = true;
  // } else {
  //   llvm::errs() << "Skipping already added caller USR to TUToUSRMap for TU:
  //   <<  " << CurrentTU_ << "\n";
  // }
  // }

  // Add the TU dependency if the callee is defined in a different TU
  auto CalleeTU = GCG_.USRToDefinedInTUMap.find(*CalleeUSR);
  if (CalleeTU != GCG_.USRToDefinedInTUMap.end()) {
    // TODO: From the build system, we could narrow the set of potential TUs
    // that are linked together with the current TU. For now, we use all TUs
    // that have a function definition for the callee.
    for (const auto &DefiningTUEntry : CalleeTU->getValue()) {
      const StringRef DefiningTU = DefiningTUEntry.getKey();
      LOG << "Found potential defining TU: " << DefiningTU << "\n";
      if (DefiningTU != CurrentTU_) {
        // Add the dependency to the TUDependencyGraph
        const auto &Result =
            GCG_.TUDependencies.addDependency(CurrentTU_, DefiningTU.str());
        if (Result) {
          LOG << "Added TU dependency to TUDependencyGraph: " << CurrentTU_
              << " -> " << DefiningTU << "\n";
          ChangesMade_ = true;
        } else {
          LOG << "Skipping already added TU dependency to TUDependencyGraph: "
              << CurrentTU_ << " -> " << DefiningTU << "\n";
        }
      } else {
        LOG << "Skipping TU dependency (same TU)\n";
      }
    }
  } else {
    LOG << "Callee TU not found in USRToDefinedInTUMap\n";
  }

  LOG << "=== Finished addCall ===\n\n";
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
    llvm::errs() << "Inserting TU: " << CurrentTU << "\n";
    std::lock_guard<std::mutex> Lock(GCG_.TUsMutex);
    const auto Result = GCG_.TUs.insert(CurrentTU);
    if (Result.second) {
      ChangesMade_ = true;
    }
  }

  llvm::errs() << "Adding independent TU to TUDependencyGraph: " << CurrentTU
               << "\n";
  GCG_.TUDependencies.addIndependentTU(CurrentTU);

  CallGraphVisitor Visitor(Context, GCG_, CurrentTU);
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());

  if (Visitor.ChangesMade()) {
    ChangesMade_ = true;
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
  for (const auto &[TU, _] : GCG.TUs) {
    llvm::errs() << "  " << TU << "\n";
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
  for (const auto &[TU, _] : GCG.TUs) {
    TUDependencies[TU.str()] = std::set<std::string>();
    llvm::errs() << "- " << TU << "\n";
  }
  llvm::errs() << "\n";

  // Debug output for function definitions
  llvm::errs() << "Function definitions in USRToFunctionMap:\n";
  for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
    llvm::errs() << "- USR: " << USR << "\n"
                 << "  Name: " << Info.FunctionName << "\n"
                 << "  TU: " << Info.TU << "\n"
                 << "  IsDefinition: " << Info.IsDefinition << "\n";
  }
  llvm::errs() << "\n";

  // Debug output for TU definitions
  llvm::errs() << "TU definitions in USRToDefinedInTUMap:\n";
  for (const auto &[USR, TUs] : GCG.USRToDefinedInTUMap) {
    llvm::errs() << "- USR: " << USR << "\n"
                 << "  TUs: ";
    for (const auto &[TU, _] : TUs) {
      llvm::errs() << TU << " ";
    }
    llvm::errs() << "\n";
  }
  llvm::errs() << "\n";

  // Process all call dependencies
  llvm::errs() << "Processing call dependencies:\n";
  for (const auto &Call : GCG.CallDependencies) {
    llvm::errs() << "\nAnalyzing call:\n"
                 << "- Caller USR: " << Call.CallerUSR << "\n"
                 << "- Callee USR: " << Call.CalleeUSR << "\n";

    auto CallerIt = GCG.USRToFunctionMap.find(Call.CallerUSR);
    if (CallerIt != GCG.USRToFunctionMap.end()) {
      llvm::errs() << "Found caller in USRToFunctionMap:\n"
                   << "- Name: " << CallerIt->second.FunctionName << "\n"
                   << "- TU: " << CallerIt->second.TU << "\n";
    } else {
      llvm::errs() << "WARNING: Caller USR not found in USRToFunctionMap\n";
    }

    auto CalleeDefTU = GCG.USRToDefinedInTUMap.find(Call.CalleeUSR);
    if (CalleeDefTU != GCG.USRToDefinedInTUMap.end()) {
      for (const auto &[CalleeTU, _] : CalleeDefTU->getValue()) {
        llvm::errs() << "Found callee TU in USRToDefinedInTUMap: " << CalleeTU
                     << "\n";
      }
    } else {
      llvm::errs() << "WARNING: Callee USR not found in USRToDefinedInTUMap\n";
    }

    if (CallerIt != GCG.USRToFunctionMap.end() &&
        CalleeDefTU != GCG.USRToDefinedInTUMap.end()) {
      const auto &CallerTU = CallerIt->getValue().TU;
      const auto &CalleeDefTUValue = CalleeDefTU->getValue();
      for (const auto &[CalleeTU, _] : CalleeDefTUValue) {
        // Skip self-dependencies
        if (CallerTU == CalleeTU) {
          llvm::errs() << "Skipping self-dependency in " << CallerTU << "\n";
          continue;
        }
        llvm::errs() << "Adding dependency: " << CallerTU << " -> " << CalleeTU
                     << "\n";
        // Add the callee's TU to the caller's dependencies
        TUDependencies[CallerTU.str().str()].emplace(CalleeTU.str());
      }
    }
  }

  // Debug output final TU dependency graph
  llvm::errs() << "\nFinal TU Dependency Graph:\n";
  for (const auto &[TU, Dependencies] : TUDependencies) {
    llvm::errs() << "TU: " << TU << "\n";
    for (const auto &Dep : Dependencies) {
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