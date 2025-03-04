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

#include "CollectExceptionInfo.h"
#include "ExceptionAnalyzer.cpp"

using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace clang::exception_scan;

static cl::OptionCategory
    ClangExtDefMapGenCategory("clang-extdefmapgen options");

int main(int argc, const char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);

  if (argc != 3) {
    llvm::errs() << "Usage: clang-exception-scan <compdb> <output-dir>";
    return 1;
  }

  const auto *CompDBPath = argv[1];
  auto ErrorMessage = std::string{};
  auto CompDB = JSONCompilationDatabase::loadFromFile(
      CompDBPath, ErrorMessage, JSONCommandLineSyntax::AutoDetect);

  llvm::outs() << "Loading compilation database " << CompDBPath << "...\n";

  if (!CompDB) {
    llvm::errs() << ErrorMessage;
    return 2;
  }

  llvm::outs() << "Compilation database " << CompDBPath << " loaded.\n";

  const auto &Files = CompDB->getAllFiles();
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

  ClangTool Tool(*CompDB, CompDB->getAllFiles());

  ExceptionContext EC;

  auto ExceptionInfoCollectorFactory =
      std::make_unique<CollectExceptionInfoActionFactory>(EC);
  int result = Tool.run(ExceptionInfoCollectorFactory.get());

  const char* OutputDir = argv[2];
  serializeExceptionInfo(EC, OutputDir);
  reportAllFunctions(EC, OutputDir);
  reportFunctionDuplications(EC, OutputDir);
  reportDefiniteMatches(EC, OutputDir);
  reportUnknownCausedMisMatches(EC, OutputDir);

  if (result != 0) {
    return result;
  }

  return result;
}
