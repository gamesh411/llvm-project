//===- ClangExtDefMapGen.cpp
//-----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===--------------------------------------------------------------------===//
//
// Clang tool which creates a list of defined functions and the files in which
// they are defined.
//
//===--------------------------------------------------------------------===//

#include "ASTBasedExceptionAnalyzer.h"
#include "CallGraphGeneratorConsumer.h"
#include "CollectExceptionInfo.h"
#include "TypeMappingConsumer.h"
#include "USRMappingConsumer.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/ThreadPool.h"
#include "llvm/Support/VirtualFileSystem.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace llvm;
using namespace clang;
using namespace clang::tooling;
using namespace clang::exception_scan;

static cl::OptionCategory
    ClangExceptionScanCategory("clang-exception-scan options");

// Command line options
static cl::opt<std::string>
    CompilationDB("compilation-db", cl::Positional,
                  cl::desc("<compilation-database.json>"), cl::Required);
static cl::opt<std::string> OutputDir("output-dir", cl::Positional,
                                      cl::desc("<output-directory>"),
                                      cl::Required);
static cl::opt<std::string>
    FileSelector("file-selector", cl::init(""),
                 cl::desc("Only analyze files containing this string"));

// Custom FrontendAction that runs multiple consumers in sequence
class ExceptionAnalyzerAction : public clang::ASTFrontendAction {
public:
  ExceptionAnalyzerAction(GlobalExceptionInfo &GCG,
                          std::atomic<bool> &ChangedFlag)
      : GCG_(GCG), ChangedFlag_(ChangedFlag) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    class ExceptionAnalyzerConsumer : public clang::ASTConsumer {
    public:
      ExceptionAnalyzerConsumer(GlobalExceptionInfo &GCG,
                                std::atomic<bool> &ChangedFlag)
          : GCG_(GCG), ChangedFlag_(ChangedFlag) {}

      void HandleTranslationUnit(ASTContext &Context) override {
        // In the main analysis run, use the AST-based analyzer
        ASTBasedExceptionAnalyzer ExceptionAnalyzer(Context, GCG_);
        for (auto const *TopLevelDecl :
             Context.getTranslationUnitDecl()->decls()) {
          if (auto *FD = dyn_cast<FunctionDecl>(TopLevelDecl)) {
            ExceptionAnalyzer.analyzeFunction(FD);
          }
        }
        if (ExceptionAnalyzer.hasChanged()) {
          ChangedFlag_.store(true, std::memory_order_relaxed);
        }
      }

    private:
      GlobalExceptionInfo &GCG_;
      std::atomic<bool> &ChangedFlag_;
    };

    return std::make_unique<ExceptionAnalyzerConsumer>(GCG_, ChangedFlag_);
  }

private:
  GlobalExceptionInfo &GCG_;
  std::atomic<bool> &ChangedFlag_;
};

// Factory for our custom action
class ExceptionAnalyzerActionFactory
    : public clang::tooling::FrontendActionFactory {
public:
  ExceptionAnalyzerActionFactory(GlobalExceptionInfo &GCG,
                                 std::atomic<bool> &ChangedFlag)
      : GCG_(GCG), ChangedFlag_(ChangedFlag) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<ExceptionAnalyzerAction>(GCG_, ChangedFlag_);
  }

private:
  GlobalExceptionInfo &GCG_;
  std::atomic<bool> &ChangedFlag_;
};

namespace {

class SynchronizedOstream {
public:
  SynchronizedOstream(llvm::raw_ostream &OS) : OS_(OS) {}
  template <typename T> SynchronizedOstream &operator<<(const T &Value) {
    std::lock_guard<std::mutex> Lock(LogMutex_);
    OS_ << Value;
    return *this;
  }

  void flush() {
    std::lock_guard<std::mutex> Lock(LogMutex_);
    OS_.flush();
  }

private:
  llvm::raw_ostream &OS_;
  std::mutex LogMutex_;
};

static SynchronizedOstream sync_outs(llvm::outs());
static SynchronizedOstream sync_errs(llvm::errs());


// Runs a Clang Tool analysis phase in parallel using a thread pool.
// Returns true on success, false on failure.
template <bool Parallel>
bool runAnalysisPhase(llvm::StringRef PhaseName,
                      const clang::tooling::CompilationDatabase &Compilations,
                      const std::vector<std::string> &SourceFiles,
                      clang::tooling::FrontendActionFactory *Factory,
                      std::atomic<bool> &FailedFlag) {
  if constexpr (Parallel) {
    std::atomic<size_t> SuccessCount{0u};
    std::atomic<size_t> FailedCount{0u};
    sync_outs << "Running " << PhaseName << " in parallel on all files... \n";
    llvm::DefaultThreadPool Pool;
    FailedFlag.store(
        false,
        std::memory_order_relaxed); // Ensure the flag is clear before starting

    llvm::ThreadPoolTaskGroup MainAnalysisTasks(Pool);

    for (const std::string &File : SourceFiles) {
      Pool.async(MainAnalysisTasks, [&Compilations, &File, Factory, &FailedFlag,
                                     &SuccessCount, &FailedCount]() {
        // Each thread needs its own ClangTool instance.
        // Each thread gets an independent copy of a VFS to allow
        // different concurrent working directories.
        IntrusiveRefCntPtr<llvm::vfs::FileSystem> FS =
            llvm::vfs::createPhysicalFileSystem();
        ClangTool Tool(Compilations, {File},
                       std::make_shared<PCHContainerOperations>(), FS);
        // Disable default error messages, we handle failure reporting.
        Tool.setPrintErrorMessage(false);

        int Result = Tool.run(Factory);
        if (Result != 0) {
          // test_and_set returns the *previous* value. If it was
          // false, this thread is the first one to set it.
          FailedFlag.store(true, std::memory_order_relaxed);
          FailedCount.fetch_add(1, std::memory_order_relaxed);
          // Optionally log the specific file that failed
          // llvm::errs() << "Error: " << PhaseName << " failed for
          // file: " << File << " ";
        } else {
          SuccessCount.fetch_add(1, std::memory_order_relaxed);
          // If a ChangedFlag is provided, assume the factory handles
          // setting it.
        }
      });
    }

    // Monitoring thread
    Pool.async([&SuccessCount, &FailedCount, &PhaseName,
                TotalJobs = SourceFiles.size()]() {
      size_t CurrentSuccess = 0u;
      size_t CurrentFailed = 0u;
      while (CurrentSuccess + CurrentFailed < TotalJobs) {
        CurrentSuccess = SuccessCount.load(std::memory_order_relaxed);
        CurrentFailed = FailedCount.load(std::memory_order_relaxed);
        sync_outs << PhaseName << ": " << CurrentSuccess + CurrentFailed << "/"
                  << TotalJobs << " (" << CurrentFailed << " failed)\r";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      // Clear the progress line
      sync_outs << std::string(80, ' ') << '\r';
      sync_outs.flush();
    });

    sync_outs << "Waiting for main analysis tasks to finish...\n";
    Pool.wait(MainAnalysisTasks); // Wait for all analysis tasks
    sync_outs << "Main analysis tasks finished\n";
    sync_outs << "Waiting for monitor task to finish...\n";
    Pool.wait(); // Wait for the monitor task
    sync_outs << "Monitor task finished\n";

    if (FailedFlag.load(std::memory_order_relaxed)) {
      sync_errs << "Error: " << PhaseName << " failed for "
                << FailedCount.load(std::memory_order_relaxed) << " file(s).\n";
      return false;
    }

    sync_outs << PhaseName << " succeeded for all "
              << SuccessCount.load(std::memory_order_relaxed) << " file(s).\n";
    return true;

    // Sequential
  } else {
    llvm::outs() << "Running " << PhaseName
                 << " sequentially on all files... \n";

    size_t SuccessCount{0u};
    size_t FailedCount{0u};
    const size_t TotalJobs = SourceFiles.size();
    for (const std::string &File : SourceFiles) {
      // Each thread needs its own ClangTool instance.
      // Each thread gets an independent copy of a VFS to allow
      // different concurrent working directories.
      IntrusiveRefCntPtr<llvm::vfs::FileSystem> FS =
          llvm::vfs::createPhysicalFileSystem();
      ClangTool Tool(Compilations, {File},
                     std::make_shared<PCHContainerOperations>(), FS);
      // Disable default error messages, we handle failure reporting.
      Tool.setPrintErrorMessage(false);

      int Result = Tool.run(Factory);
      if (Result != 0) {
        // test_and_set returns the *previous* value. If it was
        // false, this thread is the first one to set it.
        ++FailedCount;
        // Optionally log the specific file that failed
        // llvm::errs() << "Error: " << PhaseName << " failed for
        // file: " << File << " ";
      } else {
        ++SuccessCount;
        // If a ChangedFlag is provided, assume the factory handles
        // setting it.
      }

      llvm::outs() << PhaseName << ": " << SuccessCount + FailedCount << "/"
                   << TotalJobs << " (" << FailedCount << " failed)\r";
    }
    llvm::outs() << std::string(80, ' ') << '\r';
    llvm::outs().flush();

    if (FailedFlag.load(std::memory_order_relaxed)) {
      sync_errs << "Error: " << PhaseName << " failed for " << FailedCount
                << " file(s).\n";
      return false;
    }

    llvm::outs() << PhaseName << " succeeded for all " << SuccessCount
                 << " file(s).\n";
    return true;
  }
}

template <bool Parallel>
bool runAnalysisUntilFixedPoint(
    const std::string &PhaseName,
    const clang::tooling::CompilationDatabase &Compilations,
    const std::vector<std::string> &SourcePaths,
    clang::tooling::FrontendActionFactory *Factory,
    std::atomic<bool> &FailedFlag, std::atomic<bool> &ChangedFlag) {
  bool ReachedFixedPoint = false;
  bool AnalysisSuccess = true; // Assume success to enter the loop
  size_t Iteration = 0;
  while (AnalysisSuccess && !ReachedFixedPoint) {
    ++Iteration;
    sync_outs << PhaseName << " #" << Iteration << '\n';
    ChangedFlag.store(false, std::memory_order_relaxed);
    AnalysisSuccess = runAnalysisPhase<Parallel>(
        PhaseName, Compilations, SourcePaths, Factory, FailedFlag);
    const bool ChangedFlagValue = ChangedFlag.load(std::memory_order_relaxed);
    sync_outs << "ChangedFlag: " << ChangedFlagValue << '\n';
    ReachedFixedPoint = !ChangedFlagValue;
  }
  if (AnalysisSuccess) {
    assert(ReachedFixedPoint && "Analysis was updated, but fixed point was "
                                "not reached");
    sync_outs << PhaseName
              << " was updated, and fixed point was reached "
                 "after "
              << Iteration << " iterations.\n";
  } else {
    sync_errs << PhaseName << " failed to update, stopping analysis after "
              << Iteration << "iterations!\n";
  }
  return AnalysisSuccess;
}

std::vector<std::string> reverseTopologicalSortBasedOnTUDependencies(
    const std::vector<std::string> &SourcePaths,
    const clang::exception_scan::TUDependencyGraph &TUDependencies) {
  llvm::SmallVector<PathTy, 0> SortedPaths;
  TUDependencies.topologicalSort(SortedPaths);
  std::vector<std::string> Result;
  Result.reserve(SortedPaths.size());
  // Iterate in reverse order to get dependencies before dependents
  for (auto it = SortedPaths.rbegin(); it != SortedPaths.rend(); ++it) {
    Result.push_back(it->str().str());
  }
  return Result;
}

} // namespace

int main(int argc, const char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);

  // Parse command line options
  cl::ParseCommandLineOptions(argc, argv, "clang-exception-scan\n");

  // Load compilation database
  std::string ErrorMessage;
  std::unique_ptr<CompilationDatabase> Compilations =
      JSONCompilationDatabase::loadFromFile(CompilationDB, ErrorMessage,
                                            JSONCommandLineSyntax::AutoDetect);
  if (!Compilations) {
    sync_errs << "Error: " << ErrorMessage << "\n";
    return 1;
  }

  // Get all files from compilation database
  std::vector<std::string> SourcePaths = Compilations->getAllFiles();
  if (SourcePaths.empty()) {
    sync_errs << "Error: No source files found in compilation database\n";
    return 1;
  }

  // Filter source paths based on file-selector if provided
  if (!FileSelector.empty()) {
    llvm::erase_if(SourcePaths, [](const std::string &Path) {
      return Path.find(FileSelector) == std::string::npos;
    });
  }

  if (SourcePaths.empty()) {
    sync_errs << "Error: No source files match the file-selector pattern '"
              << FileSelector << "'\n";
    return 1;
  }

  sync_outs << "Files to analyze:\n";
  for (const auto &F : SourcePaths) {
    sync_outs << F << '\n';
  }
  sync_outs << "\n";

  // Create global exception info and exception context
  GlobalExceptionInfo GEI;

  // --- Phase 1: USR Mapping ---
  auto USRMappingFactory = std::make_unique<USRMappingActionFactory>(GEI);
  std::atomic<bool> USRMappingFailed{false};
  bool USRMappingSuccess = runAnalysisPhase</*Parallel=*/true>(
      "USRMapping", *Compilations, SourcePaths, USRMappingFactory.get(),
      USRMappingFailed);
  if (!USRMappingSuccess) {
    sync_errs << "USR mapping failed, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

  // --- Phase 2: Call Graph Generation ---
  std::atomic<bool> CallGraphGenerationChanged{false};
  auto CallGraphGeneratorFactory =
      std::make_unique<CallGraphGeneratorActionFactory>(
          GEI, CallGraphGenerationChanged);
  std::atomic<bool> CallGraphGeneratorFailed{false};

  bool CallGraphGeneratorSuccess =
      runAnalysisUntilFixedPoint</*Parallel=*/true>(
          "CallGraphGenerator", *Compilations, SourcePaths,
          CallGraphGeneratorFactory.get(), CallGraphGeneratorFailed,
          CallGraphGenerationChanged);

  if (!CallGraphGeneratorSuccess) {
    sync_errs
        << "Call graph information failed to update, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

  // --- Topological Sort ---
  // Order SourcePaths topologically based on the results of the pre-analysis
  const std::vector<std::string> SortedSourcePaths =
      reverseTopologicalSortBasedOnTUDependencies(SourcePaths,
                                                  GEI.TUDependencies);
  sync_outs << "Processing order based on TU dependencies:\n";
  for (const auto &Path : SortedSourcePaths) {
    sync_outs << "- " << Path << "\n";
  }

  // --- Phase 2.5: Type Mapping ---
  auto TypeMappingFactory = std::make_unique<TypeMappingActionFactory>(GEI);
  std::atomic<bool> TypeMappingFailed{false};
  bool TypeMappingSuccess = runAnalysisPhase</*Parallel=*/false>(
      "TypeMapping", *Compilations, SortedSourcePaths, TypeMappingFactory.get(),
      TypeMappingFailed);
  if (!TypeMappingSuccess) {
    sync_errs << "Type mapping failed, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

  // --- Phase 3: Main Analysis ---
  std::atomic<bool> ExceptionAnalyzerChanged{false};
  auto ExceptionAnalyzerFactory =
      std::make_unique<ExceptionAnalyzerActionFactory>(
          GEI, ExceptionAnalyzerChanged);
  std::atomic<bool> ExceptionAnalyzerFailed{false};
  bool ExceptionAnalyzerSuccess =
      runAnalysisUntilFixedPoint</*Parallel=*/false>(
          "MainAnalysis", *Compilations, SortedSourcePaths,
          ExceptionAnalyzerFactory.get(), ExceptionAnalyzerFailed,
          ExceptionAnalyzerChanged);
  if (!ExceptionAnalyzerSuccess) {
    sync_errs << "Main analysis failed, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

  const char *OutputDirPath = OutputDir.c_str();

  // ensure OutputDirPath exists
  llvm::sys::fs::create_directories(OutputDirPath);

  // Original reports
  reportAllFunctions(GEI, OutputDirPath);
  reportFunctionDuplications(GEI, OutputDirPath);
  reportDefiniteMatches(GEI, OutputDirPath, false);
  reportDefiniteMatches(GEI, OutputDirPath, true);
  reportUnknownCausedMisMatches(GEI, OutputDirPath);

  // New reports for additional data
  reportNoexceptDependees(GEI, OutputDirPath);
  reportCallDependencies(GEI, OutputDirPath);
  reportTUDependencies(GEI, OutputDirPath);

  // Report combined analysis statistics
  reportAnalysisStats(GEI, OutputDirPath);

  // Report functions called within try blocks
  reportFunctionsCalledInTryBlocks(GEI, OutputDirPath);

  // Generate call graph visualization
  std::string DotFilePath = std::string(OutputDirPath) + "/tu_dependencies.dot";
  generateDependencyDotFile(GEI, DotFilePath);

  // Detect and report cycles
  auto Cycles = detectTUCycles(GEI);
  if (!Cycles.empty()) {
    llvm::errs() << "Detected translation unit dependency cycles:\n";
    for (const auto &Cycle : Cycles) {
      llvm::errs() << "  Cycle: ";
      for (size_t i = 0; i < Cycle.size(); ++i) {
        if (i > 0)
          llvm::errs() << " -> ";
        llvm::errs() << Cycle[i];
      }
      llvm::errs() << "\n";
    }
  } else {
    llvm::errs() << "No translation unit dependency cycles detected.\n";
  }

  return 0; // Indicate overall success
}
