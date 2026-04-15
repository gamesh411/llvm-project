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
#include "NoexceptApplier.h"
#include "TypeMappingConsumer.h"
#include "USRMappingConsumer.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
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
static cl::opt<bool>
    ApplyNoexcept("apply-noexcept", cl::init(false),
                  cl::desc("Apply noexcept to definite-match functions and "
                           "write modified files to output-dir/applied/"));
static cl::opt<bool>
    ASTDiff("ast-diff", cl::init(false),
            cl::desc("Compare AST before/after noexcept application using "
                     "an in-memory VFS overlay (no files written to disk)"));
static cl::opt<bool>
    ASTDiffOnly("ast-diff-only", cl::init(false),
                cl::desc("Skip analysis phases, read definite_results.txt "
                         "from output-dir and run only the AST diff"));
static cl::opt<std::string> ProjectRoot(
    "project-root", cl::init(""),
    cl::desc("Only modify files under this path prefix (for --apply-noexcept). "
             "Defaults to the common prefix of all source files."));
static cl::opt<bool> IncludeSystemHeaders(
    "include-system-headers", cl::init(false),
    cl::desc("Also apply noexcept to functions in system headers "
             "(only meaningful with --ast-diff)"));

// AST diff filter flags — all on by default, use --no-X to disable.
static cl::opt<bool> FilterAddresses(
    "diff-filter-addresses", cl::init(true),
    cl::desc("Normalize pointer addresses in AST diff (default: on)"));
static cl::opt<bool> FilterColumns(
    "diff-filter-columns", cl::init(true),
    cl::desc("Normalize column numbers in AST diff (default: on)"));
static cl::opt<bool> FilterTrivialNoexcept(
    "diff-filter-trivial-noexcept", cl::init(true),
    cl::desc("Filter lines where the only change is noexcept on a "
             "FunctionDecl/CompoundStmt (default: on)"));
static cl::opt<bool> FilterFilePaths(
    "diff-filter-file-paths", cl::init(true),
    cl::desc("Normalize absolute file paths to basenames in AST diff "
             "(default: on)"));
static cl::opt<bool> FilterMisaligned(
    "diff-filter-misaligned", cl::init(true),
    cl::desc("Filter diff pairs where neither side relates to noexcept "
             "changes — these are structural misalignment noise "
             "(default: on)"));

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
          ChangedFlag_.store(true, std::memory_order_release);
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

struct AnalysisPhaseResult {
  std::vector<std::string> ChangedFiles;
  std::vector<std::string> FailedFiles;
};

// Runs a Clang Tool analysis phase in parallel using a thread pool.
// Returns true on success, false on failure.
AnalysisPhaseResult runAnalysisPhaseParallel(
    llvm::StringRef PhaseName,
    const clang::tooling::CompilationDatabase &Compilations,
    const std::vector<std::string> &SourceFiles,
    clang::tooling::FrontendActionFactory *Factory,
    std::atomic<bool> &ChangedFlag, TUDependencyGraph &TUDependencies) {
  AnalysisPhaseResult AnalysisPhaseResult;
  std::mutex AnalysisPhaseMutex;
  std::mutex ChangedFilesMutex;
  sync_outs << "Running " << PhaseName << " in parallel on all files... \n";
  llvm::DefaultThreadPool Pool;
  ChangedFlag.store(
      false,
      std::memory_order_release); // Ensure the flag is clear before starting

  llvm::ThreadPoolTaskGroup MainAnalysisTasks(Pool);

  std::atomic<uint64_t> FinishedCount{0u};
  for (const std::string &File : SourceFiles) {
    Pool.async(MainAnalysisTasks, [&Compilations, &File, Factory,
                                   &FinishedCount, &AnalysisPhaseResult,
                                   &AnalysisPhaseMutex, &ChangedFlag,
                                   &TUDependencies, &ChangedFilesMutex] {
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
        std::scoped_lock Lock(AnalysisPhaseMutex);
        AnalysisPhaseResult.FailedFiles.push_back(File);
      }

      // NOTE: This is a very naive approximation of the changed files.
      // As analyses overlap, we cannot be sure which analysis caused the
      // ChangedFlag to be true. So we add all files to the ChangedFiles list.
      // This could lead to additional work, but it is a very simple solution.
      // TODO: We should be able to do better by tracking which analysis caused
      // the ChangedFlag to be true.
      if (ChangedFlag.load(std::memory_order_acquire)) {
        std::scoped_lock Lock(ChangedFilesMutex);
        for (auto &&depFile : TUDependencies.getDependents(File)) {
          if (llvm::find(AnalysisPhaseResult.ChangedFiles, depFile) ==
              AnalysisPhaseResult.ChangedFiles.end()) {
            AnalysisPhaseResult.ChangedFiles.push_back(depFile.str().str());
          }
        }
      }

      FinishedCount.fetch_add(1, std::memory_order_relaxed);
    });
  }

  // Monitoring thread
  Pool.async([&AnalysisPhaseResult, &AnalysisPhaseMutex, &PhaseName,
              &FinishedCount, TotalJobs = SourceFiles.size()]() {
    uint64_t FinishedJobs = 0u;
    do {
      FinishedJobs = FinishedCount.load(std::memory_order_relaxed);
      uint64_t FailedJobs;
      {
        std::scoped_lock Lock(AnalysisPhaseMutex);
        FailedJobs = AnalysisPhaseResult.FailedFiles.size();
      }
      sync_outs << PhaseName << ": " << FinishedJobs << "/" << TotalJobs << " ("
                << FailedJobs << " failed)\r";
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (FinishedJobs < TotalJobs);
    sync_outs << std::string(80, ' ') << '\r';
    sync_outs.flush();
  });

  sync_outs << "Waiting for main analysis tasks to finish...\n";
  Pool.wait(MainAnalysisTasks); // Wait for all analysis tasks
  sync_outs << "Main analysis tasks finished\n";
  sync_outs << "Waiting for monitor task to finish...\n";
  Pool.wait(); // Wait for the monitor task
  sync_outs << "Monitor task finished\n";

  uint64_t FailedCount = AnalysisPhaseResult.FailedFiles.size();
  if (FailedCount == 0u) {
    sync_errs << "Error: " << PhaseName << " failed for " << FailedCount
              << " file(s).\n";
  }

  sync_outs << PhaseName << " succeeded for all " << SourceFiles.size()
            << " file(s).\n";

  return AnalysisPhaseResult;
}

// Sequential
AnalysisPhaseResult runAnalysisPhaseSequential(
    llvm::StringRef PhaseName,
    const clang::tooling::CompilationDatabase &Compilations,
    const std::vector<std::string> &SourceFiles,
    clang::tooling::FrontendActionFactory *Factory,
    const std::atomic<bool> &ChangedFlag,
    const TUDependencyGraph &TUDependencies) {
  AnalysisPhaseResult AnalysisPhaseResult;
  llvm::outs() << "Running " << PhaseName << " sequentially on all files... \n";

  uint64_t FinishedCount{0u};
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
      AnalysisPhaseResult.FailedFiles.push_back(File);
    }

    if (ChangedFlag.load(std::memory_order_acquire)) {
      for (auto &&File : TUDependencies.getDependents(File)) {
        if (llvm::find(AnalysisPhaseResult.ChangedFiles, File) !=
            AnalysisPhaseResult.ChangedFiles.end()) {
          continue;
        }
        AnalysisPhaseResult.ChangedFiles.push_back(File.str().str());
      }
    }

    ++FinishedCount;

    llvm::outs() << PhaseName << ": " << FinishedCount << "/" << TotalJobs
                 << " (" << AnalysisPhaseResult.FailedFiles.size()
                 << " failed)\r";
  }
  llvm::outs() << std::string(80, ' ') << '\r';
  llvm::outs().flush();

  uint64_t FailedCount = AnalysisPhaseResult.FailedFiles.size();
  if (FailedCount == 0u) {
    sync_errs << "Error: " << PhaseName << " failed for " << FailedCount
              << " file(s).\n";
  }

  sync_outs << PhaseName << " succeeded for all " << SourceFiles.size()
            << " file(s).\n";
  ;

  return AnalysisPhaseResult;
}

using AnalysisPhaseRunner = std::function<AnalysisPhaseResult(
    llvm::StringRef PhaseName,
    const clang::tooling::CompilationDatabase &Compilations,
    const std::vector<std::string> &SourceFiles,
    clang::tooling::FrontendActionFactory *Factory,
    std::atomic<bool> &ChangedFlag, TUDependencyGraph &TUDependencies)>;

bool runAnalysisUntilFixedPoint(
    const std::string &PhaseName,
    const clang::tooling::CompilationDatabase &Compilations,
    const std::vector<std::string> &SourcePaths,
    clang::tooling::FrontendActionFactory *Factory,
    std::atomic<bool> &ChangedFlag, TUDependencyGraph &TUDependencies,
    const AnalysisPhaseRunner &PhaseRunner) {
  bool AnalysisSuccess = true; // Assume success to enter the loop
  size_t Iteration = 0;

  std::vector<std::string> WorkList{SourcePaths};
  while (AnalysisSuccess && !WorkList.empty()) {
    ++Iteration;
    sync_outs << PhaseName << " #" << Iteration << '\n';
    ChangedFlag.store(false, std::memory_order_release);
    AnalysisPhaseResult AnalysisPhaseResult =
        PhaseRunner(PhaseName, Compilations, WorkList, Factory, ChangedFlag,
                    TUDependencies);
    if (AnalysisPhaseResult.FailedFiles.size() > 0) {
      sync_errs << "Warning: " << PhaseName << " failed for "
                << AnalysisPhaseResult.FailedFiles.size()
                << " file(s), continuing with remaining files.\n";
      // Remove failed files from future work lists
      std::set<std::string> FailedSet(
          AnalysisPhaseResult.FailedFiles.begin(),
          AnalysisPhaseResult.FailedFiles.end());
      std::vector<std::string> Filtered;
      for (const auto &F : AnalysisPhaseResult.ChangedFiles)
        if (FailedSet.find(F) == FailedSet.end())
          Filtered.push_back(F);
      WorkList = std::move(Filtered);
    } else {
      WorkList = AnalysisPhaseResult.ChangedFiles;
    }
  }

  if (AnalysisSuccess) {
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

  const char *OutputDirPath = OutputDir.c_str();
  llvm::sys::fs::create_directories(OutputDirPath);

  // Use SourcePaths as SortedSourcePaths initially; analysis may reorder.
  std::vector<std::string> SortedSourcePaths = SourcePaths;

  if (ASTDiffOnly) {
    // --- Fast path: skip analysis, load definite_results.txt ---
    SmallString<128> DefinitePath(OutputDirPath);
    llvm::sys::path::append(DefinitePath, "definite_results.txt");
    auto BufOrErr = llvm::MemoryBuffer::getFile(DefinitePath);
    if (!BufOrErr) {
      sync_errs << "Error: cannot read " << DefinitePath << ": "
                << BufOrErr.getError().message() << "\n";
      sync_errs << "Run without --ast-diff-only first to generate analysis "
                   "results.\n";
      return 1;
    }
    unsigned Loaded = 0;
    llvm::StringRef Content = BufOrErr.get()->getBuffer();
    while (!Content.empty()) {
      auto [Line, Rest] = Content.split('\n');
      Content = Rest;
      // Format: <USR> defined in <file>:<line>:<col>
      auto [USR, Loc] = Line.split(" defined in ");
      if (USR.empty() || Loc.empty())
        continue;
      GlobalFunctionExceptionInfo Info;
      Info.Function = USRTy(USR);
      Info.State = ExceptionState::NotThrowing;
      Info.ContainsUnknown = false;
      Info.ExceptionSpecType = EST_None;
      GEI.USRToExceptionMap[USR] = std::move(Info);
      ++Loaded;
    }
    sync_outs << "Loaded " << Loaded
              << " definite matches from previous analysis.\n";
    // Also load definite_internal_results.txt for the summary.
    SmallString<128> InternalPath(OutputDirPath);
    llvm::sys::path::append(InternalPath, "definite_internal_results.txt");
    auto IntBufOrErr = llvm::MemoryBuffer::getFile(InternalPath);
    if (IntBufOrErr) {
      llvm::StringRef IntContent = IntBufOrErr.get()->getBuffer();
      while (!IntContent.empty()) {
        auto [Line, Rest] = IntContent.split('\n');
        IntContent = Rest;
        auto [USR, Loc] = Line.split(" defined in ");
        if (USR.empty() || Loc.empty())
          continue;
        // Mark as internal linkage in the function map.
        FunctionMappingInfo FI;
        FI.USR = USRTy(USR);
        FI.IsDefinition = true;
        FI.IsInSystemHeader = false;
        FI.IsConsideredInternalLinkage = true;
        GEI.USRToFunctionMap[USR] = std::move(FI);
      }
    }
    // Populate function map for non-internal entries too.
    for (const auto &[USR, Info] : GEI.USRToExceptionMap) {
      if (!GEI.USRToFunctionMap.count(USR)) {
        FunctionMappingInfo FI;
        FI.USR = USRTy(USR);
        FI.IsDefinition = true;
        FI.IsInSystemHeader = false;
        FI.IsConsideredInternalLinkage = false;
        GEI.USRToFunctionMap[USR] = std::move(FI);
      }
    }
  } else {
    // --- Full analysis path ---

  // --- Phase 1: USR Mapping ---
  std::atomic<bool> USRMappingChanged{false};
  auto USRMappingFactory = std::make_unique<USRMappingActionFactory>(GEI);
  bool USRMappingSuccess = runAnalysisUntilFixedPoint(
      "USRMapping", *Compilations, SourcePaths, USRMappingFactory.get(),
      USRMappingChanged, GEI.TUDependencies, runAnalysisPhaseParallel);
  if (!USRMappingSuccess) {
    sync_errs << "USR mapping failed, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

  // --- Phase 2: Call Graph Generation ---
  std::atomic<bool> CallGraphGenerationChanged{false};
  auto CallGraphGeneratorFactory =
      std::make_unique<CallGraphGeneratorActionFactory>(
          GEI, CallGraphGenerationChanged);
  bool CallGraphGeneratorSuccess = runAnalysisUntilFixedPoint(
      "CallGraphGenerator", *Compilations, SourcePaths,
      CallGraphGeneratorFactory.get(), CallGraphGenerationChanged,
      GEI.TUDependencies, runAnalysisPhaseParallel);

  if (!CallGraphGeneratorSuccess) {
    sync_errs
        << "Call graph information failed to update, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

  // --- Topological Sort ---
  // Order SourcePaths topologically based on the results of the pre-analysis
  SortedSourcePaths =
      reverseTopologicalSortBasedOnTUDependencies(SourcePaths,
                                                  GEI.TUDependencies);
  sync_outs << "Processing order based on TU dependencies:\n";
  for (const auto &Path : SortedSourcePaths) {
    sync_outs << "- " << Path << "\n";
  }

  // --- Phase 2.5: Type Mapping ---
  std::atomic<bool> TypeMappingChanged{false};
  auto TypeMappingFactory = std::make_unique<TypeMappingActionFactory>(GEI);
  bool TypeMappingSuccess = runAnalysisUntilFixedPoint(
      "TypeMapping", *Compilations, SortedSourcePaths, TypeMappingFactory.get(),
      TypeMappingChanged, GEI.TUDependencies, runAnalysisPhaseSequential);
  if (!TypeMappingSuccess) {
    sync_errs << "Type mapping failed, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

  // --- Phase 3: Main Analysis ---
  std::atomic<bool> ExceptionAnalyzerChanged{false};
  auto ExceptionAnalyzerFactory =
      std::make_unique<ExceptionAnalyzerActionFactory>(
          GEI, ExceptionAnalyzerChanged);
  bool ExceptionAnalyzerSuccess = runAnalysisUntilFixedPoint(
      "MainAnalysis", *Compilations, SortedSourcePaths,
      ExceptionAnalyzerFactory.get(), ExceptionAnalyzerChanged,
      GEI.TUDependencies, runAnalysisPhaseSequential);
  if (!ExceptionAnalyzerSuccess) {
    sync_errs << "Main analysis failed, stopping analysis...\n";
    return 1; // Exit if the phase failed
  }

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

  } // end of full analysis path

  // --- Optional: Apply noexcept to disk ---
  if (ApplyNoexcept) {
    // Determine the allowed path prefix for modifications.
    std::string AllowedPrefix = ProjectRoot;
    if (AllowedPrefix.empty()) {
      llvm::SmallString<256> Common;
      for (const auto &P : SourcePaths) {
        llvm::SmallString<256> Abs(P);
        llvm::sys::fs::make_absolute(Abs);
        llvm::sys::path::remove_dots(Abs, /*remove_dot_dot=*/true);
        if (Common.empty()) {
          Common = llvm::sys::path::parent_path(Abs);
        } else {
          size_t Len = std::min(Common.size(), Abs.size());
          size_t Match = 0;
          for (size_t I = 0; I < Len; ++I) {
            if (Common[I] != Abs[I])
              break;
            Match = I + 1;
          }
          Common.resize(Match);
          while (!Common.empty() &&
                 !llvm::sys::path::is_separator(Common.back()))
            Common.pop_back();
        }
      }
      AllowedPrefix = Common.str().str();
    }
    {
      llvm::SmallString<256> Tmp(AllowedPrefix);
      llvm::sys::fs::make_absolute(Tmp);
      llvm::sys::path::remove_dots(Tmp, /*remove_dot_dot=*/true);
      while (!Tmp.empty() && llvm::sys::path::is_separator(Tmp.back()))
        Tmp.pop_back();
      AllowedPrefix = Tmp.str().str();
    }
    sync_outs << "Project root for noexcept application: " << AllowedPrefix
              << "\n";

    NoexceptApplierOptions Opts;
    Opts.AllowedPathPrefix = AllowedPrefix;
    Opts.IncludeSystemHeaders = false;

    llvm::StringMap<std::string> RewrittenFiles;
    auto ApplierFactory =
        std::make_unique<NoexceptApplierActionFactory>(GEI, RewrittenFiles, Opts);

    size_t ApplyIdx = 0;
    for (const std::string &File : SortedSourcePaths) {
      ++ApplyIdx;
      if (ApplyIdx % 100 == 0 || ApplyIdx == SortedSourcePaths.size())
        sync_outs << "apply-noexcept: " << ApplyIdx << "/"
                  << SortedSourcePaths.size() << "\n";
      IntrusiveRefCntPtr<llvm::vfs::FileSystem> FS =
          llvm::vfs::createPhysicalFileSystem();
      ClangTool Tool(*Compilations, {File},
                     std::make_shared<PCHContainerOperations>(), FS);
      Tool.setPrintErrorMessage(false);
      Tool.run(ApplierFactory.get());
    }
    sync_outs.flush();

    SmallString<128> AppliedDir(OutputDirPath);
    llvm::sys::path::append(AppliedDir, "applied");
    llvm::sys::fs::create_directories(AppliedDir);

    for (const auto &[OrigPath, Content] : RewrittenFiles) {
      SmallString<128> OutPath(AppliedDir);
      llvm::sys::path::append(OutPath, llvm::sys::path::filename(OrigPath));
      std::error_code EC;
      raw_fd_ostream Out(OutPath, EC, llvm::sys::fs::OF_Text);
      if (EC) {
        llvm::errs() << "Error writing " << OutPath << ": " << EC.message()
                      << "\n";
        continue;
      }
      Out << Content;
      sync_outs << "Wrote noexcept-applied file: " << OutPath << "\n";
    }
  }

  // --- Optional: In-memory AST diff ---
  if (ASTDiff || ASTDiffOnly) {
    NoexceptApplierOptions DiffOpts;
    DiffOpts.AllowedPathPrefix = ProjectRoot;
    DiffOpts.IncludeSystemHeaders = IncludeSystemHeaders;

    llvm::StringMap<std::string> RewrittenFiles;
    auto ApplierFactory = std::make_unique<NoexceptApplierActionFactory>(
        GEI, RewrittenFiles, DiffOpts);

    {
      std::atomic<size_t> ApplierProgress{0};
      llvm::DefaultThreadPool Pool;
      for (const std::string &File : SortedSourcePaths) {
        Pool.async([&, File] {
          IntrusiveRefCntPtr<llvm::vfs::FileSystem> FS =
              llvm::vfs::createPhysicalFileSystem();
          ClangTool Tool(*Compilations, {File},
                         std::make_shared<PCHContainerOperations>(), FS);
          Tool.setPrintErrorMessage(false);
          Tool.run(ApplierFactory.get());
          size_t Done = ApplierProgress.fetch_add(1) + 1;
          if (Done % 100 == 0 || Done == SortedSourcePaths.size())
            sync_outs << "ast-diff rewrite: " << Done << "/"
                      << SortedSourcePaths.size() << "\n";
        });
      }
      Pool.wait();
    }

    if (RewrittenFiles.empty()) {
      sync_outs << "No files were rewritten — no AST diff to produce.\n";
    } else {
      sync_outs << "Rewritten " << RewrittenFiles.size()
                << " file(s) in memory. Running AST diff...\n";

      // Determine which TUs are affected by the rewrites.
      // A TU is affected if any rewritten file could be included by it.
      // Quick check: the TU's main file was rewritten, or any rewritten
      // file shares a directory with the TU's main file or its -I paths.
      llvm::StringSet<> RewrittenAbsPaths;
      llvm::StringSet<> RewrittenDirs;
      for (const auto &[Path, Content] : RewrittenFiles) {
        llvm::SmallString<256> Abs(Path);
        llvm::sys::fs::make_absolute(Abs);
        llvm::sys::path::remove_dots(Abs, /*remove_dot_dot=*/true);
        RewrittenAbsPaths.insert(Abs);
        RewrittenDirs.insert(llvm::sys::path::parent_path(Abs));
      }

      std::vector<std::string> AffectedTUs;
      for (const std::string &File : SortedSourcePaths) {
        llvm::SmallString<256> Abs(File);
        llvm::sys::fs::make_absolute(Abs);
        llvm::sys::path::remove_dots(Abs, /*remove_dot_dot=*/true);

        // Direct hit: main file was rewritten.
        if (RewrittenAbsPaths.count(Abs)) {
          AffectedTUs.push_back(File);
          continue;
        }

        // Check -I paths from compile command against rewritten dirs.
        bool Affected = false;
        auto Commands = Compilations->getCompileCommands(File);
        for (const auto &Cmd : Commands) {
          for (size_t I = 0; I < Cmd.CommandLine.size() && !Affected; ++I) {
            llvm::StringRef Arg = Cmd.CommandLine[I];
            llvm::StringRef IncDir;
            if (Arg.starts_with("-I"))
              IncDir = Arg.size() > 2
                           ? Arg.drop_front(2)
                           : (I + 1 < Cmd.CommandLine.size()
                                  ? llvm::StringRef(Cmd.CommandLine[I + 1])
                                  : llvm::StringRef());
            if (IncDir.empty())
              continue;
            llvm::SmallString<256> AbsInc(IncDir);
            llvm::sys::fs::make_absolute(AbsInc);
            llvm::sys::path::remove_dots(AbsInc, /*remove_dot_dot=*/true);
            for (const auto &RDir : RewrittenDirs) {
              if (llvm::StringRef(RDir.getKey()).starts_with(AbsInc) ||
                  AbsInc.str().starts_with(RDir.getKey())) {
                Affected = true;
                break;
              }
            }
          }
        }
        if (Affected)
          AffectedTUs.push_back(File);
      }
      sync_outs << "TUs affected by rewrites: " << AffectedTUs.size() << " of "
                << SortedSourcePaths.size() << "\n";

      // Build overlay VFS with rewritten files at their original paths.
      auto OverlayVFS = buildOverlayVFS(RewrittenFiles);
      IntrusiveRefCntPtr<llvm::vfs::FileSystem> RealVFS =
          llvm::vfs::createPhysicalFileSystem();

      ASTDiffFilterOptions FilterOpts;
      FilterOpts.NormalizeAddresses = FilterAddresses;
      FilterOpts.NormalizeColumns = FilterColumns;
      FilterOpts.FilterTrivialNoexcept = FilterTrivialNoexcept;
      FilterOpts.NormalizeFilePaths = FilterFilePaths;
      FilterOpts.FilterMisaligned = FilterMisaligned;

      SmallString<128> DiffPath(OutputDirPath);
      llvm::sys::path::append(DiffPath, "ast_diff.txt");
      std::error_code EC;
      raw_fd_ostream DiffOut(DiffPath, EC, llvm::sys::fs::OF_Text);
      if (EC) {
        llvm::errs() << "Error opening " << DiffPath << ": " << EC.message()
                      << "\n";
      } else {
        bool AnyMeaningful = false;
        unsigned TotalMeaningfulLines = 0;
        std::vector<std::pair<std::string, std::string>> AllDiffPairs;

        // Per-TU results collected in parallel.
        struct TUDiffResult {
          std::string File;
          std::vector<std::pair<std::string, std::string>> DiffPairs;
        };
        std::vector<TUDiffResult> TUResults(AffectedTUs.size());
        std::atomic<size_t> DiffProgress{0};

        {
          llvm::DefaultThreadPool Pool;
          for (size_t I = 0; I < AffectedTUs.size(); ++I) {
            Pool.async([&, I] {
              const std::string &File = AffectedTUs[I];
              IntrusiveRefCntPtr<llvm::vfs::FileSystem> LocalRealVFS =
                  llvm::vfs::createPhysicalFileSystem();
              std::string ASTBefore =
                  dumpAST(*Compilations, File, LocalRealVFS);
              std::string ASTAfter =
                  dumpAST(*Compilations, File, OverlayVFS);

              size_t Done = DiffProgress.fetch_add(1) + 1;
              if (Done % 100 == 0 || Done == AffectedTUs.size())
                sync_outs << "ast-diff dump: " << Done << "/"
                          << AffectedTUs.size() << "\n";

              if (ASTBefore == ASTAfter)
                return;

              auto NormalizeAndSplit =
                  [&FilterOpts](
                      const std::string &S) -> std::vector<std::string> {
                std::vector<std::string> Lines;
                llvm::StringRef Ref(S);
                while (!Ref.empty()) {
                  auto [Line, Rest] = Ref.split('\n');
                  Lines.push_back(normalizeASTLine(Line, FilterOpts));
                  Ref = Rest;
                }
                return Lines;
              };

              auto BeforeLines = NormalizeAndSplit(ASTBefore);
              auto AfterLines = NormalizeAndSplit(ASTAfter);

              std::unordered_map<std::string, int> LineCounts;
              for (const auto &L : BeforeLines)
                --LineCounts[L];
              for (const auto &L : AfterLines)
                ++LineCounts[L];

              std::vector<std::pair<std::string, std::string>> DiffPairs;
              for (const auto &[Line, Count] : LineCounts) {
                if (Count == 0)
                  continue;
                std::string Marker = Count > 0 ? "+" : "-";
                unsigned AbsCount = Count > 0 ? Count : -Count;
                for (unsigned J = 0; J < AbsCount; ++J) {
                  if (FilterOpts.FilterTrivialNoexcept) {
                    bool IsTrivialNode = false;
                    static const llvm::StringRef TrivialNodes[] = {
                        "FunctionDecl",       "CXXMethodDecl",
                        "CXXConstructorDecl", "CXXDestructorDecl",
                        "CompoundStmt",
                    };
                    for (const auto &NT : TrivialNodes) {
                      if (Line.find(NT.str()) != std::string::npos) {
                        IsTrivialNode = true;
                        break;
                      }
                    }
                    if (IsTrivialNode) {
                      std::string Stripped = Line;
                      for (;;) {
                        size_t Pos = Stripped.find(" noexcept");
                        if (Pos == std::string::npos)
                          break;
                        Stripped.erase(Pos, 9);
                      }
                      for (;;) {
                        size_t Pos =
                            Stripped.find(" exceptionspec_basic_noexcept");
                        if (Pos == std::string::npos)
                          break;
                        Stripped.erase(Pos, 29);
                      }
                      auto It2 = LineCounts.find(Stripped);
                      if (It2 != LineCounts.end() && It2->second != 0 &&
                          ((Count > 0 && It2->second < 0) ||
                           (Count < 0 && It2->second > 0)))
                        continue;
                    }
                  }
                  if (FilterOpts.FilterMisaligned &&
                      Line.find("noexcept") == std::string::npos)
                    continue;
                  DiffPairs.emplace_back(Marker, Line);
                }
              }

              TUResults[I].File = File;
              TUResults[I].DiffPairs = std::move(DiffPairs);
            });
          }
          Pool.wait();
        }

        // Merge results sequentially (preserves file order).
        for (const auto &R : TUResults) {
          if (R.DiffPairs.empty())
            continue;
          AnyMeaningful = true;
          DiffOut << "=== " << R.File << " ===\n";
          for (const auto &[Marker, Line] : R.DiffPairs) {
            DiffOut << Marker << Line << "\n";
            ++TotalMeaningfulLines;
          }
          DiffOut << "\n";
          AllDiffPairs.insert(AllDiffPairs.end(), R.DiffPairs.begin(),
                              R.DiffPairs.end());
        }

        sync_outs.flush();

        if (AnyMeaningful) {
          sync_outs << "AST diff written to: " << DiffPath << " ("
                    << TotalMeaningfulLines << " meaningful diff pairs)\n";
        } else {
          sync_outs << "No meaningful AST differences found.\n";
          DiffOut << "No meaningful AST differences found.\n";
        }

        // --- Focused report: declarations that gained noexcept ---
        unsigned DeclsInSystemHeaders = 0;
        unsigned DeclsInUserCode = 0;
        {
          SmallString<128> DeclsPath(OutputDirPath);
          llvm::sys::path::append(DeclsPath, "ast_diff_decls.txt");
          std::error_code DeclsEC;
          raw_fd_ostream DeclsOut(DeclsPath, DeclsEC, llvm::sys::fs::OF_Text);
          if (!DeclsEC) {
            DeclsOut << "Declarations that gained noexcept:\n";
            for (const auto &[Marker, Line] : AllDiffPairs) {
              if (Marker != "+")
                continue;
              bool IsDecl =
                  Line.find("FunctionDecl") != std::string::npos ||
                  Line.find("CXXMethodDecl") != std::string::npos ||
                  Line.find("CXXConstructorDecl") != std::string::npos ||
                  Line.find("CXXDestructorDecl") != std::string::npos;
              if (!IsDecl || Line.find("noexcept") == std::string::npos)
                continue;
              DeclsOut << Line << "\n";
              // Heuristic: system header if path contains SDK/platform paths.
              if (Line.find("/usr/include/") != std::string::npos ||
                  Line.find("Xcode.app/") != std::string::npos ||
                  Line.find("/SDKs/") != std::string::npos)
                ++DeclsInSystemHeaders;
              else
                ++DeclsInUserCode;
            }
            sync_outs << "Decls report: " << DeclsPath << " ("
                      << (DeclsInSystemHeaders + DeclsInUserCode)
                      << " declarations)\n";
          }
        }

        // --- Focused report: call sites with changed targets ---
        // Use a custom AST visitor to collect call-site records with stable
        // identity (source locations), then compare before/after.
        unsigned NewCallTargets = 0;
        unsigned OverloadChanges = 0;
        {
          SmallString<128> CallsPath(OutputDirPath);
          llvm::sys::path::append(CallsPath, "ast_diff_callsites.txt");
          std::error_code CallsEC;
          raw_fd_ostream CallsOut(CallsPath, CallsEC, llvm::sys::fs::OF_Text);
          if (!CallsEC) {
            CallsOut << "Call sites with changed resolution:\n\n";

            // Collect per-TU call sites in parallel.
            struct TUCallResult {
              std::vector<CallSiteRecord> Before;
              std::vector<CallSiteRecord> After;
            };
            std::vector<TUCallResult> CallResults(AffectedTUs.size());
            std::atomic<size_t> CallProgress{0};

            {
              llvm::DefaultThreadPool Pool;
              for (size_t I = 0; I < AffectedTUs.size(); ++I) {
                Pool.async([&, I] {
                  IntrusiveRefCntPtr<llvm::vfs::FileSystem> LocalRealVFS =
                      llvm::vfs::createPhysicalFileSystem();
                  CallResults[I].Before = collectCallSites(
                      *Compilations, AffectedTUs[I], LocalRealVFS);
                  CallResults[I].After = collectCallSites(
                      *Compilations, AffectedTUs[I], OverlayVFS);
                  size_t Done = CallProgress.fetch_add(1) + 1;
                  if (Done % 100 == 0 || Done == AffectedTUs.size())
                    sync_outs << "ast-diff callsites: " << Done << "/"
                              << AffectedTUs.size() << "\n";
                });
              }
              Pool.wait();
            }

            // Compare results sequentially.
            for (size_t I = 0; I < AffectedTUs.size(); ++I) {
              const std::string &File = AffectedTUs[I];
              const auto &Before = CallResults[I].Before;
              const auto &After = CallResults[I].After;

              auto MakeKey = [](const CallSiteRecord &R) {
                return R.CallerLoc + "|" + R.CallLoc + "|" + R.CalleeName;
              };

              llvm::StringMap<const CallSiteRecord *> BeforeMap;
              for (const auto &R : Before)
                BeforeMap[MakeKey(R)] = &R;

              llvm::StringMap<const CallSiteRecord *> AfterMap;
              for (const auto &R : After)
                AfterMap[MakeKey(R)] = &R;

              for (const auto &[Key, AR] : AfterMap) {
                auto It = BeforeMap.find(Key);
                if (It == BeforeMap.end()) {
                  ++NewCallTargets;
                  CallsOut << "  NEW TARGET in " << File << "\n";
                  CallsOut << "    caller: " << AR->CallerName << " ("
                           << AR->CallerLoc << ")\n";
                  CallsOut << "    call at: " << AR->CallLoc << "\n";
                  CallsOut << "    callee: " << AR->CalleeName << " "
                           << AR->CalleeSig << "\n";
                  CallsOut << "    defined at: " << AR->CalleeLoc << "\n\n";
                  continue;
                }
                const CallSiteRecord *BR = It->getValue();
                if (BR->CalleeSig == AR->CalleeSig)
                  continue;
                if (BR->keyWithoutNoexcept() == AR->keyWithoutNoexcept())
                  continue;
                if (BR->CalleeLoc != AR->CalleeLoc ||
                    BR->keyWithoutNoexcept() != AR->keyWithoutNoexcept()) {
                  ++OverloadChanges;
                  CallsOut << "  OVERLOAD CHANGE in " << File << "\n";
                  CallsOut << "    caller: " << AR->CallerName << " ("
                           << AR->CallerLoc << ")\n";
                  CallsOut << "    call at: " << AR->CallLoc << "\n";
                  CallsOut << "    old callee: " << BR->CalleeName << " "
                           << BR->CalleeSig << " @ " << BR->CalleeLoc << "\n";
                  CallsOut << "    new callee: " << AR->CalleeName << " "
                           << AR->CalleeSig << " @ " << AR->CalleeLoc
                           << "\n\n";
                }
              }
            }

            sync_outs << "Call sites report: " << CallsPath << " ("
                      << OverloadChanges << " overload changes, "
                      << NewCallTargets << " new targets)\n";
          }
        }

        // --- Summary report ---
        {
          // Count total NotThrowing + EST_None in the exception map.
          unsigned TotalNotThrowingNoSpec = 0;
          {
            std::lock_guard<std::mutex> Lock(GEI.USRToExceptionMapMutex);
            for (const auto &[USR, Info] : GEI.USRToExceptionMap) {
              if (Info.State == ExceptionState::NotThrowing &&
                  Info.ExceptionSpecType == EST_None)
                ++TotalNotThrowingNoSpec;
            }
          }

          // Count definite matches by linkage.
          unsigned DefiniteTotal = 0, DefiniteInternal = 0;
          {
            std::scoped_lock Lock(GEI.USRToExceptionMapMutex,
                                  GEI.USRToFunctionMapMutex);
            for (const auto &[USR, Info] : GEI.USRToExceptionMap) {
              if (Info.State != ExceptionState::NotThrowing ||
                  Info.ExceptionSpecType != EST_None)
                continue;
              auto FuncIt = GEI.USRToFunctionMap.find(USR);
              if (FuncIt == GEI.USRToFunctionMap.end())
                continue;
              const auto &FI = FuncIt->getValue();
              if (!FI.IsDefinition || FI.IsInSystemHeader)
                continue;
              ++DefiniteTotal;
              if (FI.IsConsideredInternalLinkage)
                ++DefiniteInternal;
            }
          }

          SmallString<128> SummaryPath(OutputDirPath);
          llvm::sys::path::append(SummaryPath, "ast_diff_summary.txt");
          std::error_code SumEC;
          raw_fd_ostream SumOut(SummaryPath, SumEC, llvm::sys::fs::OF_Text);
          if (!SumEC) {
            SumOut << "=== Noexcept Impact Summary ===\n\n";
            SumOut << "Definite noexcept candidates (user code): "
                   << DefiniteTotal << "\n";
            SumOut << "  External linkage: "
                   << (DefiniteTotal - DefiniteInternal) << "\n";
            SumOut << "  Internal linkage: " << DefiniteInternal << "\n";
            SumOut << "Total NotThrowing+NoSpec in exception map: "
                   << TotalNotThrowingNoSpec << "\n";
            SumOut << "Files rewritten by applier: " << RewrittenFiles.size()
                   << "\n\n";
            SumOut << "Declarations that gained noexcept: "
                   << (DeclsInSystemHeaders + DeclsInUserCode) << "\n";
            SumOut << "  In system headers: " << DeclsInSystemHeaders << "\n";
            SumOut << "  In user code: " << DeclsInUserCode << "\n\n";
            SumOut << "Call site changes: "
                   << (OverloadChanges + NewCallTargets) << "\n";
            SumOut << "  Different overload chosen: " << OverloadChanges
                   << "\n";
            SumOut << "  New call targets: " << NewCallTargets << "\n";
            sync_outs << "Summary: " << SummaryPath << "\n";
          }
        }
      }
    }
  }

  return 0; // Indicate overall success
}
