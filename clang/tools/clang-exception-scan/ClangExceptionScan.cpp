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

#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Signals.h"
#include <clang/Analysis/CallGraph.h>
#include <string>

#include "CallGraphGeneratorConsumer.h"
#include "CollectExceptionInfo.h"
#include "ExceptionAnalyzer.cpp"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include <memory>
#include <thread>
#include <vector>

using namespace llvm;
using namespace clang;
using namespace clang::tooling;
using namespace clang::exception_scan;

static cl::OptionCategory
    ClangExceptionScanCategory("clang-exception-scan options");

// Command line options
static cl::opt<std::string> OutputDir("output-dir",
                                      cl::desc("Output directory"),
                                      cl::init("."), cl::Required);
static cl::opt<int> NumThreads("jobs", cl::desc("Number of parallel jobs"),
                               cl::init(0));

// Factory for creating CallGraphGeneratorConsumer
class CallGraphGeneratorActionFactory : public FrontendActionFactory {
public:
  explicit CallGraphGeneratorActionFactory(GlobalCallGraph &GCG) : GCG_(GCG) {}

  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<CallGraphGeneratorAction>(GCG_);
  }

private:
  GlobalCallGraph &GCG_;
};

// FrontendAction that uses CallGraphGeneratorConsumer
class CallGraphGeneratorAction : public ASTFrontendAction {
public:
  explicit CallGraphGeneratorAction(GlobalCallGraph &GCG) : GCG_(GCG) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    return std::make_unique<CallGraphGeneratorConsumer>(GCG_);
  }

private:
  GlobalCallGraph &GCG_;
};

int main(int argc, const char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);

  // Parse command line options
  llvm::Expected<CommonOptionsParser> OptionsParser =
      CommonOptionsParser::create(argc, argv, ClangExceptionScanCategory);
  if (not OptionsParser) {
    llvm::errs() << "Error: " << OptionsParser.takeError() << "\n";
    return 1;
  }

  ClangTool Tool(OptionsParser->getCompilations(),
                 OptionsParser->getSourcePathList());

  llvm::outs() << "Loading compilation database...\n";

  const auto &Files = OptionsParser->getSourcePathList();
  const auto UniqueFiles = std::set<std::string>{Files.begin(), Files.end()};

  if (Files.size() != UniqueFiles.size()) {
    llvm::errs() << "Files list in compilation database is not unique!";
    return 3;
  }

  llvm::outs() << "Files to process:\n";
  for (const auto &F : Files) {
    llvm::outs() << F << '\n';
  }
  llvm::outs() << "\n";

  // Create global call graph
  GlobalCallGraph GCG;
  auto CallGraphGeneratorFactory =
      std::make_unique<CallGraphGeneratorActionFactory>(GCG);

  int NumJobs = NumThreads;
  if (NumJobs <= 0) {
    NumJobs = std::thread::hardware_concurrency();
    if (NumJobs <= 0)
      NumJobs = 1;
  }

  llvm::outs() << "Using " << NumJobs
               << " parallel jobs for call graph generation\n";

  int result = Tool.run(CallGraphGeneratorFactory.get());

  if (result != 0) {
    llvm::errs() << "Error: Call graph generation failed\n";
    return result;
  }

  // Process files for exception analysis
  ExceptionContext EC;
  auto ExceptionInfoCollectorFactory =
      std::make_unique<CollectExceptionInfoActionFactory>(EC);
  result = Tool.run(ExceptionInfoCollectorFactory.get());

  if (result != 0) {
    llvm::errs() << "Error: Exception analysis failed\n";
    return result;
  }

  // Generate output files
  const char *OutputDirPath = OutputDir.c_str();
  serializeExceptionInfo(EC, OutputDirPath);
  reportAllFunctions(EC, OutputDirPath);
  reportFunctionDuplications(EC, OutputDirPath);
  reportDefiniteMatches(EC, OutputDirPath);
  reportUnknownCausedMisMatches(EC, OutputDirPath);

  // Generate call graph visualization
  std::string DotFilePath = std::string(OutputDirPath) + "/tu_dependencies.dot";
  generateDependencyDotFile(GCG, DotFilePath);

  // Detect and report cycles
  auto Cycles = detectTUCycles(GCG);
  if (!Cycles.empty()) {
    llvm::outs() << "Detected translation unit dependency cycles:\n";
    for (const auto &Cycle : Cycles) {
      llvm::outs() << "  Cycle: ";
      for (size_t i = 0; i < Cycle.size(); ++i) {
        if (i > 0)
          llvm::outs() << " -> ";
        llvm::outs() << Cycle[i];
      }
      llvm::outs() << "\n";
    }
  } else {
    llvm::outs() << "No translation unit dependency cycles detected.\n";
  }

  return result;
}
