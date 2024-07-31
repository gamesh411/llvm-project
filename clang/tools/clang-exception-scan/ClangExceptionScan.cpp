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
#include "ClangExceptionScanAction.hpp"
#include "ExceptionContext.hpp"
#include "clang/AST/ASTContext.h"
#include <clang/Analysis/CallGraph.h>
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Signals.h"
#include <optional>
#include <string>

using namespace llvm;
using namespace clang;
using namespace clang::tooling;

std::optional<bool> isInside(const Stmt *Candidate, const Stmt *Container) {
  SourceRange CandidateRange = Candidate->getSourceRange();
  SourceRange ContainerRange = Container->getSourceRange();

  if (CandidateRange.isInvalid() || ContainerRange.isInvalid())
    return std::nullopt;

  return ContainerRange.fullyContains(CandidateRange);
}

// NOTE: this function is copied from clang/SemaExprCXX.cpp
static void
collectPublicBases(CXXRecordDecl *RD,
                   llvm::DenseMap<CXXRecordDecl *, unsigned> &SubobjectsSeen,
                   llvm::SmallPtrSetImpl<CXXRecordDecl *> &VBases,
                   llvm::SetVector<CXXRecordDecl *> &PublicSubobjectsSeen,
                   bool ParentIsPublic) {
  for (const CXXBaseSpecifier &BS : RD->bases()) {
    CXXRecordDecl *BaseDecl = BS.getType()->getAsCXXRecordDecl();
    bool NewSubobject;
    // Virtual bases constitute the same subobject.  Non-virtual bases are
    // always distinct subobjects.
    if (BS.isVirtual())
      NewSubobject = VBases.insert(BaseDecl).second;
    else
      NewSubobject = true;

    if (NewSubobject)
      ++SubobjectsSeen[BaseDecl];

    // Only add subobjects which have public access throughout the entire chain.
    bool PublicPath = ParentIsPublic && BS.getAccessSpecifier() == AS_public;
    if (PublicPath)
      PublicSubobjectsSeen.insert(BaseDecl);

    // Recurse on to each base subobject.
    collectPublicBases(BaseDecl, SubobjectsSeen, VBases, PublicSubobjectsSeen,
                       PublicPath);
  }
}

// NOTE: this function is copied from clang/SemaExprCXX.cpp
static void getUnambiguousPublicSubobjects(
    CXXRecordDecl *RD, llvm::SmallVectorImpl<CXXRecordDecl *> &Objects) {
  llvm::DenseMap<CXXRecordDecl *, unsigned> SubobjectsSeen;
  llvm::SmallSet<CXXRecordDecl *, 2> VBases;
  llvm::SetVector<CXXRecordDecl *> PublicSubobjectsSeen;
  SubobjectsSeen[RD] = 1;
  PublicSubobjectsSeen.insert(RD);
  collectPublicBases(RD, SubobjectsSeen, VBases, PublicSubobjectsSeen,
                     /*ParentIsPublic=*/true);

  for (CXXRecordDecl *PublicSubobject : PublicSubobjectsSeen) {
    // Skip ambiguous objects.
    if (SubobjectsSeen[PublicSubobject] > 1)
      continue;

    Objects.push_back(PublicSubobject);
  }
}

void printNoexceptSuggestion(const FunctionDecl *FD,
                             const ExceptionContext &EC) {
  // exception specification if noexcept false if there are any uncaught
  // throws, otherwise it is the and-combined noexcept specification of the
  // called functions
  if (FD->getExceptionSpecType() == clang::EST_BasicNoexcept ||
      FD->getExceptionSpecType() == clang::EST_NoexceptTrue) {
    llvm::outs() << "The function is already marked noexcept!\n";
    return;
  }

  const ExceptionInfo &EI = EC.ExInfoIndex.at(FD);
  auto PotentiallyThrowingCalls = llvm::SmallVector<const FunctionDecl *>();
  for (const auto &Call : EI.Calls) {
    if (Call.Callee->getExceptionSpecType() == clang::EST_BasicNoexcept ||
        Call.Callee->getExceptionSpecType() == clang::EST_NoexceptTrue) {
      continue;
    }
    PotentiallyThrowingCalls.push_back(Call.Callee);
  }
  if (PotentiallyThrowingCalls.empty()) {
    llvm::outs() << "The function has only noexcept callees!\n";
    return;
  }

  llvm::outs() << "Exception specification: noexcept(";
  bool first = true;
  for (const auto &Call : PotentiallyThrowingCalls) {
    if (!first) {
      llvm::outs() << " && ";
    }
    first = false;
    llvm::outs() << "noexcept(";
    llvm::outs() << EC.ShortNameIndex.at(Call) << "()";
    llvm::outs() << ")";
  }
  llvm::outs() << ")";
}

void printExceptionInfoRec(const FunctionDecl *FD, const ExceptionContext &EC,
                           int IndentLevel = 0, bool ShowLocation = false) {
  const ExceptionInfo &EI = EC.ExInfoIndex.at(FD);
  std::string Indent(2 * IndentLevel, ' ');

  if (IndentLevel == 0) {
    llvm::outs() << Indent << "Name:\n";
    llvm::outs() << Indent << EC.ShortNameIndex.at(FD) << "\n";
  }

  if (!EI.Tries.empty()) {
    llvm::outs() << Indent << "tries:\n";

    for (const TryInfo &Try : EI.Tries) {
      llvm::outs() << Indent << "  - " << Try.Stmt;
      if (ShowLocation)
        llvm::outs() << "@" << Try.Location;
      llvm::outs() << "\n";
    }
  }

  // -------------------
  // Matching exceptions
  // -------------------
  // Each try block associates with a number of handlers, these handlers form a
  // handler sequence. When an exception is thrown from a try block, the
  // handlers in the sequence are tried in order of appearance to match the
  // exception. A handler is a match for an exception object of type E if any of
  // the following conditions is satisfied:
  //   - The handler is of type “possibly cv-qualified T” or “lvalue reference
  //   to possibly cv-qualified T”, and any of the following conditions is
  //   satisfied:
  //     - E and T are the same type (ignoring the top-level cv-qualifiers).
  //     - T is an unambiguous public base class of E.
  // The handler is of type “possibly cv-qualified T” or const T& where T is a
  // pointer or pointer-to-member type, and any of the following conditions is
  // satisfied: E is a pointer or pointer-to-member type that can be converted
  // to T by at least one of the following conversions:
  //   - A standard pointer conversion not involving conversions to pointers to
  //   private or protected or ambiguous classes.
  //   - A function pointer conversion. (since C++17)
  //   - A qualification conversion.
  //   - E is std::nullptr_t. (since C++11)
  //
  // source: https://en.cppreference.com/w/cpp/language/catch
  //
  auto UncaughtThrows = EI.Throws;
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
              bool CanBeCaught = false;
              if (Catch.Stmt->getCaughtType() ==
                  Throw.Expr->getSubExpr()->getType()) {
                CanBeCaught = true;
              } else {
                if (Throw.Expr->getSubExpr() == nullptr) {
                  llvm::outs() << "This is a rethrow, TODO\n";
                } else {
                  CXXRecordDecl *CatchRecordType =
                      Catch.Stmt->getCaughtType()->getAsCXXRecordDecl();
                  CXXRecordDecl *ThrowRecordType =
                      Throw.Expr->getSubExpr()->getType()->getAsCXXRecordDecl();
                  if (CatchRecordType && ThrowRecordType) {
                    llvm::SmallVector<clang::CXXRecordDecl *>
                        UnambiguousPublicSubobjects;
                    getUnambiguousPublicSubobjects(ThrowRecordType,
                                                   UnambiguousPublicSubobjects);
                    CanBeCaught = llvm::is_contained(
                        UnambiguousPublicSubobjects, CatchRecordType);
                  }
                }
              }
              if (CanBeCaught) {
                UncaughtThrows.erase(
                    std::find_if(UncaughtThrows.begin(), UncaughtThrows.end(),
                                 [TE = Throw.Expr](const ThrowInfo &TI) {
                                   return TE == TI.Expr;
                                 }));
              }
            }
          }
        }
      }
    }
  }

  llvm::outs() << Indent << "uncaught throws:\n";
  for (const ThrowInfo &Throw : UncaughtThrows) {
    llvm::outs() << Indent << "  - " << Throw.Description;
    if (ShowLocation)
      llvm::outs() << "@" << Throw.Location;
    llvm::outs() << "\n";
  }

  if (!EI.Catches.empty()) {
    llvm::outs() << Indent << "catches:\n";
    for (const CatchInfo &Catch : EI.Catches) {
      llvm::outs() << Indent << "  - " << Catch.Description;

      if (ShowLocation)
        llvm::outs() << "@" << Catch.Location;
      llvm::outs() << "\n";
    }
  }

  if (!EI.Calls.empty()) {
    llvm::outs() << Indent << "calls:\n";
    for (const CallInfo &Call : EI.Calls) {
      llvm::outs() << Indent << "  - " << EC.ShortNameIndex.at(Call.Callee);
      if (ShowLocation)
        llvm::outs() << "@" << Call.Location;
      llvm::outs() << "\n";
    }
  }
}

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

  ExceptionContext EC;
  auto FunctionCollector = std::make_unique<ExceptionScanAction>(EC);

  int result = Tool.run(newExceptionScanActionFactory(EC).get());

  for (const auto &FD : EC.FunctionsVisited) {
    if (!EC.IsInMainFileIndex.at(FD))
      continue;

    llvm::outs() << "Exception Info:\n";
    printExceptionInfoRec(FD, EC);

    llvm::outs() << "\nNoexcept Suggestion:\n";
    printNoexceptSuggestion(FD, EC);
  }

  return result;
}
