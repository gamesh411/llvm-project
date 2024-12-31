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

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Signals.h"
#include <clang/Analysis/CallGraph.h>
#include <string>
#include <unordered_map>

#include "CollectExceptionInfo.h"

using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::cross_tu;
using namespace clang::tooling;
using namespace clang::exception_scan;

static cl::OptionCategory
    ClangExtDefMapGenCategory("clang-extdefmapgen options");

int main(int argc, const char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);

  if (argc != 2) {
    llvm::errs() << "Usage: clang-exception-scan <compdb>";
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

  llvm::outs() << "Compilation database " << argv[1] << " loaded.\n";

  const auto &Files = CompDB->getAllFiles();
  const auto UniqueFiles = std::set<std::string>{Files.begin(), Files.end()};

  if (Files.size() != UniqueFiles.size()) {
    llvm::errs() << "Files list in compilation database is not unique!";
    return 3;
  }

  llvm::outs() << "Files to process:\n";

  for (const auto &F : Files)
    llvm::outs() << F << '\n';

  llvm::outs() << "\n";

  ClangTool Tool(*CompDB, CompDB->getAllFiles());

  auto ExceptionInfoCollectorFactory =
      std::make_unique<CollectExceptionInfoActionFactory>();
  int result = Tool.run(ExceptionInfoCollectorFactory.get());

  if (result != 0) {
    return result;
  }

  bool ShowLocation = true;
  auto &EC = ExceptionInfoCollectorFactory->EC;
  llvm::outs() << '\n';
  for (const auto &FD : EC.FunctionsVisited) {

    if (!EC.IsInMainFileIndex[FD])
      continue;

    const ExceptionInfo &EI = EC.ExInfoIndex[FD];

    auto UncaughtThrows = EI.Throws;

    auto rec_print_ei = [&](const FunctionDecl *FD, int level = 0) {
      llvm::outs() << "Function:\n";

      // ASTDumper P(llvm::outs(), /*ShowColors=*/false);
      // P.Visit(FD->getBody());

      auto rec_print_ei_impl = [&](const FunctionDecl *FD, int level,
                                   auto &rec_ref) -> void {
        std::string indent(2 * level, ' ');

        if (level == 0) {
          llvm::outs() << indent << "Name:\n";
          llvm::outs() << indent << EC.ShortNameIndex[FD] << "\n";
        }

        if (!EI.Tries.empty()) {
          llvm::outs() << indent << "tries:\n";

          for (const TryInfo &Try : EI.Tries) {
            llvm::outs() << indent << "  - " << Try.Stmt;
            if (ShowLocation)
              llvm::outs() << "@" << Try.Location;
            llvm::outs() << "\n";
          }
        }

        if (!EI.Throws.empty()) {
          for (const ThrowInfo &Throw : EI.Throws) {
            // if a throw statement is inside a try statement, then
            // lets examine all the catch statements, and if a catch statement
            // matches the throw type, then lets remove the throw statement
            // from the list of throws.
            // FIXME: this is ugly
            for (const TryInfo &Try : EI.Tries) {
              if (isInside(Throw.Expr, Try.Stmt)) {
                for (const CatchInfo &Catch : EI.Catches) {
                  if (isInside(Catch.Stmt, Try.Stmt)) {
                    if (Catch.Stmt->getCaughtType() ==
                        Throw.Expr->getSubExpr()->getType()) {
                      const auto &AsConst = std::as_const(UncaughtThrows);
                      UncaughtThrows.erase(
                          std::find_if(AsConst.begin(), AsConst.end(),
                                       [TE = Throw.Expr](const ThrowInfo &TI) {
                                         return TE == TI.Expr;
                                       }));
                    }
                  }
                }
              }
            }
          }

          llvm::outs() << indent << "uncaught throws:\n";
          for (const ThrowInfo &Throw : UncaughtThrows) {
            llvm::outs() << indent << "  - " << Throw.Description;
            if (ShowLocation)
              llvm::outs() << "@" << Throw.Location;
            llvm::outs() << "\n";
          }
        }

        if (!EI.Catches.empty()) {
          llvm::outs() << indent << "catches:\n";
          for (const CatchInfo &Catch : EI.Catches) {
            llvm::outs() << indent << "  - " << Catch.Description;

            if (ShowLocation)
              llvm::outs() << "@" << Catch.Location;
            llvm::outs() << "\n";
          }
        }

        if (!EI.Calls.empty()) {
          llvm::outs() << indent << "calls:\n";
          for (const CallInfo &Call : EI.Calls) {
            llvm::outs() << indent << "  - " << EC.ShortNameIndex[Call.Callee];
            if (ShowLocation)
              llvm::outs() << "@" << Call.Location;
            llvm::outs() << "\n";

            // rec_ref(Call.Callee, level + 1, rec_ref);
          }
        }
      };
      rec_print_ei_impl(FD, level, rec_print_ei_impl);
    };

    rec_print_ei(FD);

    // exception specification if noexcept false if there are any uncaught
    // throws, otherwise it is the and-combined noexcept specification of the
    // called functions
    llvm::outs() << "Exception specification:\n";

    llvm::outs() << "  noexcept";
    if (FD->getExceptionSpecType() == clang::EST_BasicNoexcept ||
        FD->getExceptionSpecType() == clang::EST_NoexceptTrue) {
      continue;
    }

    auto PotentiallyThrowingCalls = llvm::SmallVector<const FunctionDecl *>();
    for (const auto &Call : EI.Calls) {
      if (Call.Callee->getExceptionSpecType() == clang::EST_BasicNoexcept ||
          Call.Callee->getExceptionSpecType() == clang::EST_NoexceptTrue) {
        continue;
      }
      PotentiallyThrowingCalls.push_back(Call.Callee);
    }
    if (PotentiallyThrowingCalls.empty()) {
      continue;
    }
    llvm::outs() << "(";
    bool first = true;
    for (const auto &Call : PotentiallyThrowingCalls) {
      if (!first) {
        llvm::outs() << " && ";
      }
      first = false;
      llvm::outs() << "noexcept(";
      llvm::outs() << EC.ShortNameIndex[Call] << "()";
      llvm::outs() << ")";
    }
    llvm::outs() << ")";
  }

  return result;
}
