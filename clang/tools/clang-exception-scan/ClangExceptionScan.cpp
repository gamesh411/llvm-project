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

// Custom FrontendAction that runs multiple consumers in sequence
class MultiConsumerAction : public clang::ASTFrontendAction {
public:
  MultiConsumerAction(GlobalExceptionInfo &GCG, ExceptionContext &EC)
      : GCG_(GCG), EC_(EC) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    // Create a consumer that will run all our consumers in sequence
    class SequentialConsumer : public clang::ASTConsumer {
    public:
      SequentialConsumer(GlobalExceptionInfo &GCG, ExceptionContext &EC,
                         CompilerInstance &CI, StringRef InFile)
          : GCG_(GCG), EC_(EC), CI_(CI), InFile_(InFile) {}

      void HandleTranslationUnit(ASTContext &Context) override {
        // Run USRMappingConsumer first
        USRMappingConsumer USRConsumer(InFile_.str(), GCG_);
        USRConsumer.HandleTranslationUnit(Context);

        // Then run CallGraphGeneratorConsumer
        CallGraphGeneratorConsumer CallGraphConsumer(InFile_.str(), GCG_);
        CallGraphConsumer.HandleTranslationUnit(Context);

        // Then run ExceptionAnalyzer
        ExceptionAnalyzer ExceptionAnalyzer(Context);
        for (auto const *TopLevelDecl :
             Context.getTranslationUnitDecl()->decls()) {
          if (auto *FD = dyn_cast<FunctionDecl>(TopLevelDecl)) {
            auto AI = ExceptionAnalyzer.analyzeFunction(FD);

            // Collect exception info
            auto const *FirstDecl = FD->getFirstDecl();
            auto FirstDeclaredInFile = std::string{
                CI_.getSourceManager().getFilename(FirstDecl->getLocation())};
            auto const *Definition = FD->getDefinition();

            auto DefinedInFile = std::string{};
            if (Definition)
              DefinedInFile = std::string{CI_.getSourceManager().getFilename(
                  Definition->getLocation())};
            auto *Identifier = FirstDecl->getIdentifier();
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
            bool IsInMainFile =
                CI_.getSourceManager().isInMainFile(FD->getOuterLocStart());

            EC_.InfoPerFunction.push_back({FirstDeclaredInFile, DefinedInFile,
                                           FunctionName, FunctionUSRName,
                                           ExceptionTypeList, Behaviour, ES,
                                           ContainsUnknown, IsInMainFile});
          }
        }

        // Finally run NoexceptDependeeConsumer
        NoexceptDependeeConsumer NoexceptConsumer(InFile_.str(), GCG_);
        NoexceptConsumer.HandleTranslationUnit(Context);
      }

    private:
      GlobalExceptionInfo &GCG_;
      ExceptionContext &EC_;
      CompilerInstance &CI_;
      StringRef InFile_;
    };

    return std::make_unique<SequentialConsumer>(GCG_, EC_, CI, InFile);
  }

private:
  GlobalExceptionInfo &GCG_;
  ExceptionContext &EC_;
};

// Factory for our custom action
class MultiConsumerActionFactory
    : public clang::tooling::FrontendActionFactory {
public:
  MultiConsumerActionFactory(GlobalExceptionInfo &GCG, ExceptionContext &EC)
      : GCG_(GCG), EC_(EC) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<MultiConsumerAction>(GCG_, EC_);
  }

private:
  GlobalExceptionInfo &GCG_;
  ExceptionContext &EC_;
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

  llvm::outs() << "Files to process:\n";
  for (const auto &F : SourcePaths) {
    llvm::outs() << F << '\n';
  }
  llvm::outs() << "\n";

  // Create global exception info and exception context
  GlobalExceptionInfo GEI;
  ExceptionContext EC;

  // Create our custom action factory that will run all consumers
  auto ActionFactory = std::make_unique<MultiConsumerActionFactory>(GEI, EC);

  // Create and run the tool
  ClangTool Tool(*Compilations, SourcePaths);
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
