#include "CollectExceptionInfo.h"
#include "GlobalExceptionInfo.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm> // for std::sort
#include <sstream>
#include <system_error> // for std::error_code

using namespace llvm;
using namespace clang;
using namespace clang::exception_scan;

namespace {
// Helper to open a file for writing
std::unique_ptr<raw_fd_ostream> openOutputFile(StringRef Prefix,
                                               StringRef Suffix) {
  SmallString<128> Path(Prefix);
  sys::path::append(Path, Suffix);
  std::error_code EC;
  auto Out = std::make_unique<raw_fd_ostream>(Path, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "Error opening file " << Path << ": " << EC.message() << "\n";
    return nullptr;
  }
  return Out;
}
} // namespace

void clang::exception_scan::reportAllFunctions(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "all_functions.txt");
  if (!Out)
    return;

  *Out << "All functions:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      *Out << USR << " defined in " << Info.TU << '\n';
    }
  }
}

void clang::exception_scan::reportFunctionDuplications(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "function_duplications.txt");
  if (!Out)
    return;

  // Count occurrences of each function
  llvm::StringMap<unsigned> FunctionOccurrence;
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      ++FunctionOccurrence[USR];
    }
  }

  *Out << "Functions that appear in multiple translation units:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      if (FunctionOccurrence[USR] > 1) {
        *Out << USR << " defined in " << Info.TU << " translation units\n";
      }
    }
  }
}

void clang::exception_scan::reportDefiniteMatches(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "definite_results.txt");
  if (!Out)
    return;

  struct DefiniteResult {
    llvm::StringRef USR;
    llvm::StringRef TU;
    llvm::StringRef SourceLocFile;
    unsigned SourceLocLine;
    unsigned SourceLocColumn;
  };

  llvm::SmallVector<DefiniteResult, 32> DefiniteResults;
  {
    std::scoped_lock Lock(GCG.USRToExceptionMapMutex,
                          GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToExceptionMap) {
      if (Info.State == ExceptionState::NotThrowing &&
          Info.ExceptionSpecType == EST_None) {
        const auto FuncIt = GCG.USRToFunctionMap.find(USR);
        if (FuncIt == GCG.USRToFunctionMap.end()) {
          llvm::errs() << "USR not found in USRToFunctionMap: " << USR << "\n";
          continue;
        }
        const auto &FuncInfo = FuncIt->getValue();
        if (FuncInfo.IsDefinition && !FuncInfo.IsInSystemHeader) {
          DefiniteResults.push_back(
              DefiniteResult{USR, FuncInfo.TU, FuncInfo.SourceLocFile,
                             FuncInfo.SourceLocLine, FuncInfo.SourceLocColumn});
        }
      }
    }
  }

  llvm::sort(DefiniteResults,
             [](const DefiniteResult &LHS, const DefiniteResult &RHS) {
               if (LHS.SourceLocFile != RHS.SourceLocFile) {
                 return LHS.SourceLocFile < RHS.SourceLocFile;
               }
               if (LHS.SourceLocLine != RHS.SourceLocLine) {
                 return LHS.SourceLocLine < RHS.SourceLocLine;
               }
               return LHS.SourceLocColumn < RHS.SourceLocColumn;
             });

  *Out << "Functions that could be marked noexcept, but are not:\n";
  for (const auto &Result : DefiniteResults) {
    *Out << Result.USR << " defined in " << Result.SourceLocFile << ':'
         << Result.SourceLocLine << ':' << Result.SourceLocColumn << '\n';
  }
}

void clang::exception_scan::reportUnknownCausedMisMatches(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "unknown_caused_mismatches.txt");
  if (!Out)
    return;

  struct UnknownCausedMismatch {
    USRTy USR;
    PathTy TU;
    PathTy SourceLocFile;
    unsigned SourceLocLine;
    unsigned SourceLocColumn;
    llvm::SmallVector<USRTy, 2> CallsToUnknown;
  };

  llvm::SmallVector<UnknownCausedMismatch, 32> UnknownCausedMismatches;
  {
    std::scoped_lock Lock(GCG.USRToExceptionMapMutex, GCG.USRToFunctionMapMutex,
                          GCG.CallDependenciesMutex);
    for (const auto &[USR, Info] : GCG.USRToExceptionMap) {
      if (Info.State == ExceptionState::Unknown && Info.ContainsUnknown) {
        auto FuncIt = GCG.USRToFunctionMap.find(USR);
        if (FuncIt == GCG.USRToFunctionMap.end()) {
          llvm::errs() << "USR not found in USRToFunctionMap: " << USR << "\n";
          continue;
        }
        const auto &FuncInfo = FuncIt->getValue();

        // Collect all calls of this function to functions that have unknown
        // exception state.
        llvm::SmallVector<USRTy, 2> CallsToUnknown;
        for (const auto &Call : GCG.CallDependencies) {
          if (Call.CallerUSR == USR) {
            auto CalleeIt = GCG.USRToExceptionMap.find(Call.CalleeUSR);
            if (CalleeIt == GCG.USRToExceptionMap.end()) {
              llvm::errs() << "Callee USR not found in USRToExceptionMap: "
                           << Call.CalleeUSR << "\n";
              continue;
            }
            const auto &CalleeInfo = CalleeIt->getValue();
            if (CalleeInfo.State == ExceptionState::Unknown) {
              CallsToUnknown.push_back(Call.CalleeUSR);
            }
          }
        }

        // NOTE: Lets not restrict the reporting to just non-system-header
        // functions, as unknown functions can be defined in system headers.
        if (FuncInfo.IsDefinition) {
          UnknownCausedMismatches.push_back(
              {USR, FuncInfo.TU, FuncInfo.SourceLocFile, FuncInfo.SourceLocLine,
               FuncInfo.SourceLocColumn, std::move(CallsToUnknown)});
        }
      }
    }
  }

  llvm::sort(UnknownCausedMismatches, [](const UnknownCausedMismatch &LHS,
                                         const UnknownCausedMismatch &RHS) {
    if (LHS.SourceLocFile != RHS.SourceLocFile) {
      return LHS.SourceLocFile < RHS.SourceLocFile;
    }
    return LHS.SourceLocColumn < RHS.SourceLocColumn;
  });

  *Out << "Functions with unknown exception state because they contain unknown "
       << "calls:\n";
  for (const auto &Result : UnknownCausedMismatches) {
    *Out << Result.USR << " defined in " << Result.SourceLocFile << ':'
         << Result.SourceLocLine << ':' << Result.SourceLocColumn << '\n';
    for (const auto &Call : Result.CallsToUnknown) {
      *Out << "  Calls to unknown: " << Call << '\n';
    }
  }
}

// New reporting functions for the additional data
void clang::exception_scan::reportNoexceptDependees(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "noexcept_dependees.txt");
  if (!Out)
    return;

  *Out << "Functions that appear in noexcept clauses:\n";
  for (const auto &Info : GCG.NoexceptDependees) {
    *Out << "Function: " << Info.FunctionName << "\n";
    *Out << "  USR: " << Info.USR << "\n";
    *Out << "  TU: " << Info.TU << "\n";
    *Out << "  Location: " << Info.NoexceptLocFile << ":"
         << Info.NoexceptLocLine << ":" << Info.NoexceptLocColumn << "\n";
  }
}

void clang::exception_scan::reportCallDependencies(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "call_dependencies.txt");
  if (!Out)
    return;

  *Out << "Function call dependencies:\n";
  for (const auto &Call : GCG.CallDependencies) {
    *Out << "Caller: " << Call.CallerUSR << "\n";
    *Out << "Callee: " << Call.CalleeUSR << "\n";
    *Out << "Location: " << Call.CallLocFile << ":" << Call.CallLocLine << ":"
         << Call.CallLocColumn << "\n";
  }
}

void clang::exception_scan::reportTUDependencies(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "tu_dependencies.txt");
  if (!Out)
    return;

  *Out << "Translation Unit Dependencies:\n";
  for (const auto &Dependency : GCG.TUDependencies.getAllTUs()) {
    *Out << Dependency << " -> ";
    for (const auto &Dependency :
         GCG.TUDependencies.getDependencies(Dependency)) {
      *Out << Dependency << " ";
    }
    *Out << "\n";
  }
}

// Implementation for the combined statistics report function
void clang::exception_scan::reportAnalysisStats(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  auto Out = openOutputFile(PathPrefix, "analysis_stats.txt");
  if (!Out)
    return;

  *Out << "Total function definitions: " << GCG.TotalFunctionDefinitions.load()
       << "\n";
  *Out << "Total function definitions not in system headers: "
       << GCG.TotalFunctionDefinitionsNotInSystemHeaders.load() << "\n";

  *Out << "Total try blocks: " << GCG.TotalTryBlocks.load() << "\n";
  *Out << "Total try blocks not in system headers: "
       << GCG.TotalTryBlocksNotInSystemHeaders.load() << "\n";

  *Out << "Total catch handlers: " << GCG.TotalCatchHandlers.load() << "\n";
  *Out << "Total catch handlers not in system headers: "
       << GCG.TotalCatchHandlersNotInSystemHeaders.load() << "\n";

  *Out << "Total throw expressions: " << GCG.TotalThrowExpressions.load()
       << "\n";
  *Out << "Total throw expressions not in system headers: "
       << GCG.TotalThrowExpressionsNotInSystemHeaders.load() << "\n";

  *Out << "Total calls potentially within try blocks: "
       << GCG.TotalCallsPotentiallyWithinTryBlocks.load() << "\n";
  *Out << "Total calls potentially within try blocks not in system headers: "
       << GCG.TotalCallsPotentiallyWithinTryBlocksNotInSystemHeaders.load()
       << "\n";
}

// Report functions called within try blocks
void clang::exception_scan::reportFunctionsCalledInTryBlocks(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  auto Out = openOutputFile(PathPrefix, "calls_in_try_blocks.txt");
  if (!Out)
    return;

  *Out << "Functions called from within a try block:\n";

  // Structure to hold info for sorting
  struct CalledInTryInfo {
    StringRef USR;
    StringRef SourceLocFile;
    unsigned SourceLocLine;
    unsigned SourceLocColumn;
  };

  SmallVector<CalledInTryInfo, 32> Results;
  {
    // Lock both maps needed for this operation
    std::scoped_lock Lock(GCG.CalledWithinTryUSRSetMutex,
                          GCG.USRToFunctionMapMutex);
    for (const auto &Entry : GCG.CalledWithinTryUSRSet) {
      StringRef USR = Entry.getKey();
      auto FuncIt = GCG.USRToFunctionMap.find(USR);
      if (FuncIt != GCG.USRToFunctionMap.end()) {
        const auto &FuncInfo = FuncIt->getValue();
        // Store info, preferably from the definition if available
        Results.push_back({USR, FuncInfo.SourceLocFile, FuncInfo.SourceLocLine,
                           FuncInfo.SourceLocColumn});
      } else {
        // Optionally handle cases where a USR from the set isn't in the map,
        // though this shouldn't typically happen if collection is correct.
        // For now, just add the USR with dummy location data.
        Results.push_back({USR, "<unknown_file>", 0, 0});
      }
    }
  }

  // Sort results by source location
  llvm::sort(Results,
             [](const CalledInTryInfo &LHS, const CalledInTryInfo &RHS) {
               if (LHS.SourceLocFile != RHS.SourceLocFile) {
                 return LHS.SourceLocFile < RHS.SourceLocFile;
               }
               if (LHS.SourceLocLine != RHS.SourceLocLine) {
                 return LHS.SourceLocLine < RHS.SourceLocLine;
               }
               return LHS.SourceLocColumn < RHS.SourceLocColumn;
             });

  // Print sorted results
  for (const auto &Result : Results) {
    *Out << Result.USR << " defined in " << Result.SourceLocFile << ':'
         << Result.SourceLocLine << ':' << Result.SourceLocColumn << '\n';
  }
}
