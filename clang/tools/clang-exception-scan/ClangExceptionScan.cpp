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
#include <clang/CrossTU/CrossTranslationUnit.h>
#include <string>

#include "ASTBasedExceptionAnalyzer.h"
#include "CallGraphGeneratorConsumer.h"
#include "CollectExceptionInfo.h"
#include "ExceptionAnalyzer.h"
#include "NoexceptDependeeConsumer.h"
#include "USRMappingConsumer.h"
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
class MultiConsumerAction : public clang::ASTFrontendAction {
public:
  MultiConsumerAction(GlobalExceptionInfo &GCG, ExceptionContext &EC,
                      bool PreAnalysis = false)
      : GCG_(GCG), EC_(EC), PreAnalysis_(PreAnalysis) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    // Create a consumer that will run all our consumers in sequence
    class SequentialConsumer : public clang::ASTConsumer {
    public:
      SequentialConsumer(GlobalExceptionInfo &GCG, ExceptionContext &EC,
                         StringRef InFile, bool PreAnalysis)
          : GCG_(GCG), EC_(EC), InFile_(InFile), PreAnalysis_(PreAnalysis) {}

      void HandleTranslationUnit(ASTContext &Context) override {
        Context_ = &Context; // Store for use in isSystemHeader
        // Get canonical file path
        auto &SM = Context.getSourceManager();
        auto MainFileID = SM.getMainFileID();
        auto MainFileLoc = SM.getLocForStartOfFile(MainFileID);
        StringRef MainFileName = SM.getFilename(MainFileLoc);

        if (MainFileName.empty()) {
          llvm::errs() << "Warning: Empty translation unit name, skipping\n";
          return;
        }

        if (PreAnalysis_) {
          // Run USRMappingConsumer first
          USRMappingConsumer USRConsumer(MainFileName.str(), GCG_);
          USRConsumer.HandleTranslationUnit(Context);

          // Then run CallGraphGeneratorConsumer
          bool Stabilized = false;
          unsigned Iteration = 0;
          do {
            llvm::errs() << "Running CallGraphGeneratorConsumer iteration "
                         << Iteration << "\n";
            CallGraphGeneratorConsumer CallGraphConsumer(MainFileName.str(),
                                                         GCG_);
            CallGraphConsumer.HandleTranslationUnit(Context);
            Stabilized = !CallGraphConsumer.ChangesMade();
            Iteration++;
          } while (!Stabilized && Iteration < 10);

          if (!Stabilized) {
            llvm::errs()
                << "CallGraphGeneratorConsumer did not stabilize after "
                << Iteration << " iterations\n";
          }
          return;
        }

        // In the main analysis run, use the AST-based analyzer
        ASTBasedExceptionAnalyzer ExceptionAnalyzer(Context, GCG_);
        for (auto const *TopLevelDecl :
             Context.getTranslationUnitDecl()->decls()) {
          if (auto *FD = dyn_cast<FunctionDecl>(TopLevelDecl)) {
            // Skip system header functions
            llvm::errs() << "Analyzing function: " << FD->getNameAsString()
                         << "\n";
            if (SM.isInSystemHeader(FD->getLocation())) {
              llvm::errs() << "Skipping system header function...\n";
              continue;
            }

            auto AI = ExceptionAnalyzer.analyzeFunction(FD);

            // Get canonical file paths for function locations
            auto FirstDeclLoc = FD->getFirstDecl()->getLocation();
            auto FirstDeclaredInFile =
                std::string{SM.getFilename(FirstDeclLoc)};

            auto DefinedInFile = [&FD, &SM]() {
              std::string Result = "<unknown>";
              auto const *Definition = FD->getDefinition();
              if (Definition) {
                auto DefinitionLoc = Definition->getLocation();
                Result = std::string{SM.getFilename(DefinitionLoc)};
              }
              return Result;
            }();

            // In single-TU mode (with file-selector), only report functions
            // from the main file In multi-TU mode, report functions in their
            // declared location
            bool IsMainFileDecl = SM.isInMainFile(FirstDeclLoc);
            if (IsMainFileDecl) {
              auto *Identifier = FD->getIdentifier();
              auto FunctionName = std::string{};
              if (Identifier)
                FunctionName = std::string{Identifier->getName()};

              auto FunctionUSRName =
                  cross_tu::CrossTranslationUnitContext::getLookupName(FD)
                      .value_or("<no_usr_name>");

              auto ss = std::stringstream{};
              for (auto const &T : AI.ThrowEvents) {
                std::string ExceptionTypeName = T.Type.getAsString();
                ss << ExceptionTypeName << ", ";
              }
              auto view = std::string_view{ss.str()};
              if (view.size() > 2)
                view.remove_suffix(2);
              auto ExceptionTypeList = std::string{view};

              auto Behaviour = AI.State;
              auto ES = FD->getExceptionSpecType();
              bool ContainsUnknown = AI.ContainsUnknown;
              bool IsInMainFile = SM.isInMainFile(FD->getOuterLocStart());

              EC_.InfoPerFunction.push_back({FirstDeclaredInFile, DefinedInFile,
                                             FunctionName, FunctionUSRName,
                                             ExceptionTypeList, Behaviour, ES,
                                             ContainsUnknown, IsInMainFile});
            }
          }
        }

        // Finally run NoexceptDependeeConsumer
        NoexceptDependeeConsumer NoexceptConsumer(MainFileName.str(), GCG_);
        NoexceptConsumer.HandleTranslationUnit(Context);
      }

    private:
      GlobalExceptionInfo &GCG_;
      ExceptionContext &EC_;
      StringRef InFile_;
      bool PreAnalysis_;
      ASTContext *Context_; // Added to support isSystemHeader
    };

    return std::make_unique<SequentialConsumer>(GCG_, EC_, InFile,
                                                PreAnalysis_);
  }

private:
  GlobalExceptionInfo &GCG_;
  ExceptionContext &EC_;
  bool PreAnalysis_;
};

// Factory for our custom action
class MultiConsumerActionFactory
    : public clang::tooling::FrontendActionFactory {
public:
  MultiConsumerActionFactory(GlobalExceptionInfo &GCG, ExceptionContext &EC,
                             bool PreAnalysisOnly = false)
      : GCG_(GCG), EC_(EC), PreAnalysisOnly_(PreAnalysisOnly) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<MultiConsumerAction>(GCG_, EC_, PreAnalysisOnly_);
  }

private:
  GlobalExceptionInfo &GCG_;
  ExceptionContext &EC_;
  bool PreAnalysisOnly_;
};

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
    llvm::errs() << "Error: " << ErrorMessage << "\n";
    return 1;
  }

  // Get all files from compilation database
  std::vector<std::string> SourcePaths = Compilations->getAllFiles();
  if (SourcePaths.empty()) {
    llvm::errs() << "Error: No source files found in compilation database\n";
    return 1;
  }

  // Filter source paths based on file-selector if provided
  if (!FileSelector.empty()) {
    llvm::erase_if(SourcePaths, [](const std::string &Path) {
      return Path.find(FileSelector) == std::string::npos;
    });
  }

  if (SourcePaths.empty()) {
    llvm::errs() << "Error: No source files match the file-selector pattern '"
                 << FileSelector << "'\n";
    return 1;
  }

  llvm::errs() << "Files to analyze:\n";
  for (const auto &F : SourcePaths) {
    llvm::errs() << F << '\n';
  }
  llvm::errs() << "\n";

  // Create global exception info and exception context
  GlobalExceptionInfo GEI;
  ExceptionContext EC;

  // First run: Pre-analysis on build complete USR and call graph
  // info
  llvm::errs() << "Running pre-analysis on all files...\n";
  auto PreAnalysisFactory =
      std::make_unique<MultiConsumerActionFactory>(GEI, EC, true);
  ClangTool PreAnalysisTool(*Compilations, SourcePaths);
  int preResult = PreAnalysisTool.run(PreAnalysisFactory.get());
  if (preResult != 0) {
    llvm::errs() << "Error: Pre-analysis failed\n";
    return preResult;
  }

  // Order SourcePaths topologically based on the results of the pre-analysis
  const std::vector<std::string> SortedSourcePaths = [&GEI]() {
    llvm::SmallVector<PathTy, 0> SortedSourcePaths;
    GEI.TUDependencies.topologicalSort(SortedSourcePaths);
    std::vector<std::string> Result;
    // iterate in reverse order and add to Result
    for (auto it = SortedSourcePaths.rbegin(); it != SortedSourcePaths.rend();
         ++it) {
      Result.push_back(it->str().str());
    }
    return Result;
  }();
  llvm::errs() << "Reverse topologically sorted TU dependencies:\n";
  for (const auto &Path : SortedSourcePaths) {
    llvm::errs() << Path << '\n';
  }

  // Second run: Detailed analysis
  llvm::errs() << "Running detailed analysis on selected files...\n";
  auto ActionFactory =
      std::make_unique<MultiConsumerActionFactory>(GEI, EC, false);
  ClangTool Tool(*Compilations, SortedSourcePaths);
  int result = Tool.run(ActionFactory.get());

  if (result != 0) {
    llvm::errs() << "Error: Analysis failed\n";
    return result;
  }

  // Generate output files
  const char *OutputDirPath = OutputDir.c_str();

  // Original reports
  serializeExceptionInfo(EC, OutputDirPath);
  reportAllFunctions(EC, OutputDirPath);
  reportFunctionDuplications(EC, OutputDirPath);
  reportDefiniteMatches(EC, OutputDirPath);
  reportUnknownCausedMisMatches(EC, OutputDirPath);

  // New reports for additional data
  reportNoexceptDependees(GEI, OutputDirPath);
  reportCallDependencies(GEI, OutputDirPath);
  reportTUDependencies(GEI, OutputDirPath);

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

  return result;
}
